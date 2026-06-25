/// `DTLSServerEngine` datagram receive, ClientHello cookie path, server-flight
/// crypto, client-flight verification, and action translation.
///
/// Mirrors the host `DTLSConnection.processReceivedDatagram` +
/// `DTLSServerHandshakeHandler` drive logic byte-for-byte, Embedded-clean. The
/// HelloVerifyRequest cookie is bound to `clientAddress || client_random ||
/// cipher_suites` and minted/verified through the injected HMAC closures
/// (fail-closed); the ServerKeyExchange signing and the client CertificateVerify
/// verification go through the injected signer / verifier. X.509 stays OUT.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import DTLSWireCore
import DTLSHandshakeCore
import DTLSRecordCore

extension DTLSServerEngine {

    // MARK: - receive

    /// Feeds a received UDP datagram. `remoteAddress` binds the
    /// HelloVerifyRequest cookie to the client's transport address.
    public mutating func receive(
        _ datagram: Span<UInt8>,
        from remoteAddress: Span<UInt8>
    ) throws(DTLSEngineError) -> DTLSEngineOutput {
        guard phase != .failed else { throw .protocolFailure(reason: "connection in failed state") }
        guard phase != .closed else { throw .connectionClosed }
        guard !isProcessing else {
            throw .internalError(reason: "concurrent DTLS datagram processing is not allowed")
        }
        isProcessing = true
        defer { isProcessing = false }

        let data = datagram.facadeArrayLocal()
        let addr = remoteAddress.facadeArrayLocal()
        guard data.count <= Self.maxBufferSize else { throw .bufferOverflow }

        var output = DTLSEngineOutput()
        flights.responseReceived()

        do {
            try processDatagram(data, remoteAddress: addr, into: &output)
        } catch {
            phase = .failed
            throw error
        }

        if !output.datagramsToSend.isEmpty {
            flights.startFlight(output.datagramsToSend)
        }
        return output
    }

    private mutating func processDatagram(
        _ data: [UInt8],
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        var offset = 0
        while offset < data.count {
            let outcome = try record.decodeRecord(from: data, at: offset)
            switch outcome {
            case .insufficientData:
                return
            case .discarded(let consumed, let reason):
                appendAnomaly(reason, into: &output)
                offset += consumed
            case .record(let contentType, let fragment, let consumed):
                offset += consumed
                let stop = try handleRecord(
                    contentType: contentType,
                    fragment: fragment,
                    remoteAddress: remoteAddress,
                    into: &output
                )
                if stop { return }
            }
        }
    }

    private mutating func handleRecord(
        contentType: DTLSContentType,
        fragment: [UInt8],
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) -> Bool {
        switch contentType {
        case .handshake:
            try ingestHandshakeRecord(fragment, remoteAddress: remoteAddress, into: &output)
            return false
        case .changeCipherSpec:
            try installReadKeysAndAdvance()
            do { try fsm.processChangeCipherSpec() }
            catch { throw .from(core: error) }
            return false
        case .applicationData:
            output.applicationData.append(contentsOf: fragment)
            return false
        case .alert:
            return try handleAlert(fragment, into: &output)
        }
    }

    private mutating func ingestHandshakeRecord(
        _ recordFragment: [UInt8],
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        let fragments: [(header: DTLSHandshakeHeader, body: [UInt8])]
        do { fragments = try HandshakeReassemblyBuffer.parseMessages(from: recordFragment) }
        catch { throw .from(wire: error) }

        for fragment in fragments {
            let complete: [UInt8]?
            do { complete = try reassembly.addFragment(header: fragment.header, body: fragment.body) }
            catch { throw .from(wire: error) }
            guard let message = complete else { continue }
            try dispatchHandshakeMessage(message, remoteAddress: remoteAddress, into: &output)
        }
    }

    private mutating func dispatchHandshakeMessage(
        _ rawMessage: [UInt8],
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        let (header, body) = try decodeHandshakeMessage(rawMessage)

        // ClientHello is routed to the dedicated cookie path.
        if header.messageType == .clientHello {
            try handleClientHello(header: header, body: body, rawMessage: rawMessage, remoteAddress: remoteAddress, into: &output)
            return
        }

        let result: DTLSServerHandshake<C>.IngestResult
        do {
            result = try fsm.ingest(header: header, body: body, rawMessage: rawMessage)
        } catch {
            throw .from(core: error)
        }

        switch result {
        case .actions(let actions):
            try applyActions(actions, into: &output)
        case .computeSharedSecret(let clientPublicKey):
            try acceptClientKeyExchange(clientPublicKey: clientPublicKey, into: &output)
        case .verifyCertificateVerify(let handshakeHash, let rawCV):
            try verifyClientCertificateVerify(body: body, handshakeHash: handshakeHash, rawMessage: rawCV)
        }

        if remoteCertificateDER == nil, let der = fsm.clientCertificateDER {
            remoteCertificateDER = der
        }
    }

    // MARK: - ClientHello / cookie path

    private mutating func handleClientHello(
        header: DTLSHandshakeHeader,
        body: [UInt8],
        rawMessage: [UInt8],
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        let outcome: DTLSServerHandshake<C>.ClientHelloOutcome
        do { outcome = try fsm.ingestClientHello(header: header, body: body) }
        catch { throw .from(core: error) }

        switch outcome {
        case .needCookie(let clientHello):
            try emitHelloVerifyRequest(clientHello: clientHello, remoteAddress: remoteAddress, into: &output)

        case .verifyCookie(let clientHello):
            try acceptCookieClientHello(
                clientHello: clientHello,
                rawMessage: rawMessage,
                remoteAddress: remoteAddress,
                into: &output
            )
        }
    }

    /// Mints a HelloVerifyRequest cookie (injected HMAC) and emits it.
    private mutating func emitHelloVerifyRequest(
        clientHello: DTLSClientHello,
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        guard let makeCookie = configuration.makeCookie else {
            throw .invalidConfiguration(reason: "no makeCookie seam")
        }
        let material = Self.cookieBindingMaterial(
            clientAddress: remoteAddress,
            clientRandom: clientHello.random,
            cipherSuites: clientHello.cipherSuites
        )
        let cookie = makeCookie(material)
        let hvrBody = Self.encodeHelloVerifyRequestBody(cookie: cookie)
        let actions: [DTLSCoreAction]
        do { actions = try fsm.emitHelloVerifyRequest(helloVerifyRequestBody: hvrBody) }
        catch { throw .from(core: error) }
        try applyActions(actions, into: &output)
    }

    /// Verifies the presented cookie (injected HMAC, fail-closed) and builds the
    /// signed server flight. The core rejects an invalid cookie before the flight
    /// is used (the `cookieValid: false` path).
    private mutating func acceptCookieClientHello(
        clientHello: DTLSClientHello,
        rawMessage: [UInt8],
        remoteAddress: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        guard let verifyCookie = configuration.verifyCookie else {
            throw .invalidConfiguration(reason: "no verifyCookie seam")
        }
        let material = Self.cookieBindingMaterial(
            clientAddress: remoteAddress,
            clientRandom: clientHello.random,
            cipherSuites: clientHello.cipherSuites
        )
        let cookieValid = verifyCookie(clientHello.cookie, material)

        guard let selectedSuite = selectCipherSuite(from: clientHello.cipherSuites) else {
            if cookieValid {
                // Valid cookie but no suite match is a real negotiation failure.
                throw .protocolFailure(reason: "no matching DTLS cipher suite")
            }
            // Invalid cookie: let the core fail-close on the cookie check.
            let inputs = DTLSServerHandshake<C>.ServerFlightInputs(
                serverRandom: [UInt8](repeating: 0, count: 32),
                certificateBody: [],
                serverKeyExchangeBody: []
            )
            do {
                _ = try fsm.acceptCookieAndBuildFlight(
                    clientHello: clientHello,
                    rawMessage: rawMessage,
                    cookieValid: cookieValid,
                    selectedSuite: .ecdheEcdsaWithAes128GcmSha256,
                    inputs: inputs
                )
            } catch {
                throw .from(core: error)
            }
            return
        }

        // Build the signed server-flight inputs (only meaningful for a valid cookie;
        // the core rejects an invalid cookie first).
        let inputs = try buildServerFlightInputs(
            clientHello: clientHello,
            selectedSuite: selectedSuite,
            cookieValid: cookieValid
        )
        let actions: [DTLSCoreAction]
        do {
            actions = try fsm.acceptCookieAndBuildFlight(
                clientHello: clientHello,
                rawMessage: rawMessage,
                cookieValid: cookieValid,
                selectedSuite: selectedSuite,
                inputs: inputs
            )
        } catch {
            throw .from(core: error)
        }
        try applyActions(actions, into: &output)
    }

    /// Builds the server random + Certificate body + signed ServerKeyExchange body.
    /// Returns placeholder inputs for the invalid-cookie path (never sent — the core
    /// throws `cookieMismatch` before they are used).
    private mutating func buildServerFlightInputs(
        clientHello: DTLSClientHello,
        selectedSuite: DTLSCipherSuite,
        cookieValid: Bool
    ) throws(DTLSEngineError) -> DTLSServerHandshake<C>.ServerFlightInputs {
        guard cookieValid else {
            return DTLSServerHandshake<C>.ServerFlightInputs(
                serverRandom: [UInt8](repeating: 0, count: 32),
                certificateBody: [],
                serverKeyExchangeBody: []
            )
        }
        guard let randomBytes = configuration.randomBytes,
              let ecdheGenerate = configuration.ecdheGenerate,
              let sign = configuration.sign,
              let signingScheme = configuration.signingScheme else {
            throw .invalidConfiguration(reason: "no crypto seams for server flight")
        }
        let serverRandom = randomBytes(32)

        let certMessage = CertificateMessage(certificates: configuration.certificateChainDER)
        let certBody: [UInt8]
        do { certBody = try certMessage.encodeBytes() }
        catch { throw .from(wire: error) }

        // ECDHE key for the server (P-256 — WebRTC/libp2p convention).
        let namedGroup: NamedGroup = .secp256r1
        let pair = try ecdheGenerate(namedGroup)
        keyExchangeHandle = pair.privateHandle
        keyExchangeGroup = namedGroup

        // Sign `client_random || server_random || ec_params`.
        let params: [UInt8]
        do { params = try ServerKeyExchange.encodeParams(namedGroup: namedGroup, publicKey: pair.publicKey) }
        catch { throw .from(wire: error) }
        var signed = clientHello.random
        signed.append(contentsOf: serverRandom)
        signed.append(contentsOf: params)
        let signature = try sign(signed)

        let ske = ServerKeyExchange(
            namedGroup: namedGroup,
            publicKey: pair.publicKey,
            signatureScheme: signingScheme,
            signature: signature
        )
        let skeBody: [UInt8]
        do { skeBody = try ske.encodeBytes() }
        catch { throw .from(wire: error) }

        return DTLSServerHandshake<C>.ServerFlightInputs(
            serverRandom: serverRandom,
            certificateBody: certBody,
            serverKeyExchangeBody: skeBody
        )
    }

    // MARK: - Client flight (ECDHE + CertificateVerify verify)

    private mutating func acceptClientKeyExchange(
        clientPublicKey: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        guard let ecdheAgree = configuration.ecdheAgree,
              let handle = keyExchangeHandle, let group = keyExchangeGroup else {
            throw .internalError(reason: "no ECDHE state for ClientKeyExchange")
        }
        let sharedSecret = try ecdheAgree(group, handle, clientPublicKey)
        let actions: [DTLSCoreAction]
        do { actions = try fsm.acceptClientKeyExchange(sharedSecret: sharedSecret) }
        catch { throw .from(core: error) }
        try applyActions(actions, into: &output)
    }

    private mutating func verifyClientCertificateVerify(
        body: [UInt8],
        handshakeHash: [UInt8],
        rawMessage: [UInt8]
    ) throws(DTLSEngineError) {
        var valid = false
        if let certDER = fsm.clientCertificateDER {
            let cv: DTLSWireCore.CertificateVerify
            do { cv = try DTLSWireCore.CertificateVerify.decode(from: body) }
            catch { throw .from(wire: error) }
            guard let verify = configuration.verifyPeerSignature else {
                throw .invalidConfiguration(reason: "no verifyPeerSignature seam")
            }
            valid = try verify([certDER], cv.signature, handshakeHash)
        }
        // The core records the CertificateVerify into the transcript only on success
        // and fails closed on `valid == false`.
        do { try fsm.acceptClientCertificateVerify(signatureValid: valid, rawMessage: rawMessage) }
        catch { throw .from(core: error) }
    }

    // MARK: - Alerts

    private mutating func handleAlert(
        _ fragment: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) -> Bool {
        guard fragment.count >= 2 else {
            output.anomalies.append(.malformedAlert)
            return false
        }
        let level = fragment[0]
        let description = fragment[1]
        if description == 0 { // close_notify
            output.peerClosed = true
            phase = .closed
            return true
        }
        if level == 2 { // fatal
            phase = .failed
            throw .fatalAlert(code: description, reason: "peer sent fatal alert \(description)")
        }
        return false
    }

    // MARK: - Action translation

    mutating func applyActions(
        _ actions: [DTLSCoreAction],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        var recordBytes: [UInt8] = []
        for action in actions {
            switch action {
            case .sendMessage(let msg):
                let encoded = try record.encodeRecord(contentType: .handshake, plaintext: msg)
                recordBytes.append(contentsOf: encoded)
            case .sendChangeCipherSpec:
                let encoded = try record.encodeRecord(contentType: .changeCipherSpec, plaintext: [0x01])
                recordBytes.append(contentsOf: encoded)
                try installWriteKeys()
            case .keysAvailable(let keyBlock, let suite):
                pendingKeyBlock = keyBlock
                negotiatedCipherSuite = suite
            case .expectChangeCipherSpec:
                break
            case .handshakeComplete:
                try finalizeHandshake()
                output.handshakeComplete = true
            }
        }
        if !recordBytes.isEmpty {
            output.datagramsToSend.append(recordBytes)
        }
    }

    /// Installs write keys from the pending key block (server write side).
    private mutating func installWriteKeys() throws(DTLSEngineError) {
        guard let kb = pendingKeyBlock, let suite = negotiatedCipherSuite else {
            throw .internalError(reason: "no pending key block at CCS")
        }
        try record.setWriteKeys(cipherSuite: suite, key: kb.serverWriteKey, fixedIV: kb.serverWriteIV)
    }

    /// Installs read keys from the pending key block (server reads client side).
    private mutating func installReadKeysAndAdvance() throws(DTLSEngineError) {
        guard let kb = pendingKeyBlock, let suite = negotiatedCipherSuite else {
            throw .internalError(reason: "no pending key block at peer CCS")
        }
        try record.setReadKeys(cipherSuite: suite, key: kb.clientWriteKey, fixedIV: kb.clientWriteIV)
    }

    private mutating func finalizeHandshake() throws(DTLSEngineError) {
        if remoteCertificateDER == nil, let der = fsm.clientCertificateDER {
            remoteCertificateDER = der
        }
        try runCertificateValidator()
        phase = .connected
    }

    private mutating func runCertificateValidator() throws(DTLSEngineError) {
        guard let validate = configuration.validateCertificate else { return }
        let chain: [[UInt8]] = remoteCertificateDER.map { [$0] } ?? []
        validatedPeerIdentifier = try validate(chain)
    }

    // MARK: - Anomaly mapping

    private func appendAnomaly(
        _ reason: DTLSRecordDiscardReason,
        into output: inout DTLSEngineOutput
    ) {
        switch reason {
        case .replayed: output.anomalies.append(.replayed)
        case .tooOld: output.anomalies.append(.tooOld)
        case .authenticationFailed: output.anomalies.append(.authenticationFailed)
        case .malformed: output.anomalies.append(.malformed)
        case .epochMismatch: break
        }
    }

    // MARK: - Cookie binding material + HVR encode (byte-identical to host)

    /// `clientAddress<0..2^16-1> || client_random<0..2^8-1> || cipher_suites<0..2^16-1>`.
    static func cookieBindingMaterial(
        clientAddress: [UInt8],
        clientRandom: [UInt8],
        cipherSuites: [DTLSCipherSuite]
    ) -> [UInt8] {
        var writer = ByteWriter()
        do {
            try writer.writeVector16(clientAddress)
            try writer.writeVector8(clientRandom)
            var suitesWriter = ByteWriter()
            for suite in cipherSuites {
                suite.encode(writer: &suitesWriter)
            }
            try writer.writeVector16(suitesWriter.finishArray())
        } catch {
            // A wire-length overflow on cookie material is a programmer-contract
            // violation (addresses / randoms / suite lists are bounded); trap loudly.
            fatalError("DTLS cookie binding material exceeded a wire length bound")
        }
        return writer.finishArray()
    }

    /// Encodes the HelloVerifyRequest body (`server_version(2) || cookie<0..255>`).
    static func encodeHelloVerifyRequestBody(cookie: [UInt8]) -> [UInt8] {
        var writer = ByteWriter()
        // DTLS 1.2 ProtocolVersion = 0xFEFD.
        writer.writeUInt8(0xFE)
        writer.writeUInt8(0xFD)
        do {
            try writer.writeVector8(cookie)
        } catch {
            fatalError("DTLS HelloVerifyRequest encoding exceeded a wire length bound")
        }
        return writer.finishArray()
    }
}
