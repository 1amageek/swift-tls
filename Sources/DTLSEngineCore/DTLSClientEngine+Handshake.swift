/// `DTLSClientEngine` datagram receive, handshake-message dispatch, FSM-crypto
/// satisfaction, and action translation.
///
/// Mirrors the host `DTLSConnection.processReceivedDatagram` +
/// `DTLSClientHandshakeHandler` drive logic byte-for-byte, Embedded-clean: it
/// decodes each record through ``DTLSRecordEngine``, reassembles fragmented
/// handshake messages through ``DTLSWireCore/HandshakeReassemblyBuffer``, dispatches
/// each complete message to ``DTLSHandshakeCore/DTLSClientHandshake``, and satisfies
/// the FSM's crypto requests (ECDHE / SKE-signature verify / CertificateVerify sign)
/// through the injected ``DTLSEngineConfiguration`` closures. X.509 stays OUT.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import DTLSWireCore
import DTLSHandshakeCore
import DTLSRecordCore

extension DTLSClientEngine {

    // MARK: - receive

    /// Feeds a received UDP datagram and returns the aggregate effects.
    public mutating func receive(_ datagram: Span<UInt8>) throws(DTLSEngineError) -> DTLSEngineOutput {
        guard phase != .failed else { throw .protocolFailure(reason: "connection in failed state") }
        guard phase != .closed else { throw .connectionClosed }
        guard !isProcessing else {
            throw .internalError(reason: "concurrent DTLS datagram processing is not allowed")
        }
        isProcessing = true
        defer { isProcessing = false }

        let data = datagram.facadeArrayLocal()
        guard data.count <= Self.maxBufferSize else { throw .bufferOverflow }

        var output = DTLSEngineOutput()
        // Receiving any datagram cancels the pending retransmission.
        flights.responseReceived()

        do {
            try processDatagram(data, into: &output)
        } catch {
            phase = .failed
            throw error
        }

        if !output.datagramsToSend.isEmpty {
            flights.startFlight(output.datagramsToSend)
        }
        return output
    }

    /// Decodes and processes every record in the datagram (RFC 6347 §4.1.2.x).
    private mutating func processDatagram(
        _ data: [UInt8],
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
                let stop = try handleRecord(contentType: contentType, fragment: fragment, into: &output)
                if stop { return }
            }
        }
    }

    /// Handles one decoded record. Returns `true` if processing must stop (peer
    /// close_notify / fatal alert) so later records in the datagram are ignored.
    private mutating func handleRecord(
        contentType: DTLSContentType,
        fragment: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) -> Bool {
        switch contentType {
        case .handshake:
            try ingestHandshakeRecord(fragment, into: &output)
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

    /// Reassembles + dispatches every complete handshake message in a record.
    private mutating func ingestHandshakeRecord(
        _ recordFragment: [UInt8],
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
            try dispatchHandshakeMessage(message, into: &output)
        }
    }

    /// Decodes the (header, body) of a complete handshake message and drives the FSM.
    private mutating func dispatchHandshakeMessage(
        _ rawMessage: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        let (header, body) = try decodeHandshakeMessage(rawMessage)

        let result: DTLSClientHandshake<C>.IngestResult
        do {
            result = try fsm.ingest(header: header, body: body, rawMessage: rawMessage)
        } catch {
            throw .from(core: error)
        }

        switch result {
        case .actions(let actions):
            try applyActions(actions, into: &output)

        case .rebuildClientHelloWithCookie(let cookie):
            try rebuildClientHelloWithCookie(cookie, into: &output)

        case .verifyServerKeyExchange(let ske):
            try verifyServerKeyExchange(ske)

        case .buildClientFlight(let namedGroup, let serverPublicKey):
            try buildClientFlight(namedGroup: namedGroup, serverPublicKey: serverPublicKey, into: &output)
        }

        // Surface the peer certificate as soon as the FSM has it (Certificate msg).
        if remoteCertificateDER == nil, let der = fsm.serverCertificateDER {
            remoteCertificateDER = der
        }
    }

    // MARK: - FSM crypto satisfaction (injected closures)

    private mutating func rebuildClientHelloWithCookie(
        _ cookie: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        guard let random = clientRandom else {
            throw .internalError(reason: "missing client random for cookie retry")
        }
        let clientHello = DTLSClientHello(
            random: random,
            cookie: cookie,
            cipherSuites: configuration.supportedCipherSuites
        )
        let body: [UInt8]
        do { body = try clientHello.encodeBytes() }
        catch { throw .from(wire: error) }

        let actions: [DTLSCoreAction]
        do { actions = try fsm.resendClientHelloWithCookie(clientHelloBody: body) }
        catch { throw .from(core: error) }
        try applyActions(actions, into: &output)
    }

    private mutating func verifyServerKeyExchange(
        _ ske: ServerKeyExchange
    ) throws(DTLSEngineError) {
        // Verify the server signature against its certificate (X.509, injected).
        // The signed data is `client_random || server_random || ec_params`.
        let valid: Bool
        if let certDER = fsm.serverCertificateDER {
            guard let clientRandom else {
                throw .internalError(reason: "missing client random")
            }
            guard let serverRandom = fsm.negotiatedServerRandom else {
                throw .internalError(reason: "missing server random")
            }
            let params: [UInt8]
            do { params = try ServerKeyExchange.encodeParams(namedGroup: ske.namedGroup, publicKey: ske.publicKey) }
            catch { throw .from(wire: error) }
            var signed = clientRandom
            signed.append(contentsOf: serverRandom)
            signed.append(contentsOf: params)
            guard let verify = configuration.verifyPeerSignature else {
                throw .invalidConfiguration(reason: "no verifyPeerSignature seam")
            }
            valid = try verify([certDER], ske.signature, signed)
        } else {
            // No certificate seen — preserve the legacy behaviour, which only
            // verified the SKE signature when a certificate was present.
            valid = true
        }
        do { try fsm.acceptServerKeyExchange(signatureValid: valid) }
        catch { throw .from(core: error) }
    }

    private mutating func buildClientFlight(
        namedGroup: NamedGroup,
        serverPublicKey: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) {
        guard let ecdheGenerate = configuration.ecdheGenerate,
              let ecdheAgree = configuration.ecdheAgree,
              let sign = configuration.sign,
              let signingScheme = configuration.signingScheme else {
            throw .invalidConfiguration(reason: "no crypto seams for client flight")
        }

        // Generate our ECDHE key and compute the shared secret.
        let pair = try ecdheGenerate(namedGroup)
        keyExchangeHandle = pair.privateHandle
        keyExchangeGroup = namedGroup
        let sharedSecret = try ecdheAgree(namedGroup, pair.privateHandle, serverPublicKey)

        // Our own Certificate message body.
        let certMessage = CertificateMessage(certificates: configuration.certificateChainDER)
        let certBody: [UInt8]
        do { certBody = try certMessage.encodeBytes() }
        catch { throw .from(wire: error) }

        let inputs = DTLSClientHandshake<C>.ClientFlightInputs(
            sharedSecret: sharedSecret,
            clientPublicKey: pair.publicKey,
            certificateBody: certBody
        )

        // The core derives keys + transcript and returns the CertificateVerify hash.
        let cvRequest: DTLSClientHandshake<C>.CertificateVerifyRequest
        do { cvRequest = try fsm.buildClientFlight(inputs: inputs) }
        catch { throw .from(core: error) }

        // Sign the CertificateVerify over the transcript hash (injected signer).
        let signature = try sign(cvRequest.handshakeHash)
        let cv = DTLSWireCore.CertificateVerify(signatureScheme: signingScheme, signature: signature)
        let cvBody: [UInt8]
        do { cvBody = try cv.encodeBytes() }
        catch { throw .from(wire: error) }

        let actions: [DTLSCoreAction]
        do { actions = try fsm.finishClientFlight(certificateVerifyBody: cvBody) }
        catch { throw .from(core: error) }
        try applyActions(actions, into: &output)
    }

    // MARK: - Alerts

    /// Returns `true` if processing must stop (close_notify / fatal alert).
    private mutating func handleAlert(
        _ fragment: [UInt8],
        into output: inout DTLSEngineOutput
    ) throws(DTLSEngineError) -> Bool {
        // RFC 5246 alert: level(1) || description(1). Malformed → surface, discard.
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

    // MARK: - Action translation (encrypt at epoch + install keys)

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
                // Install write keys AFTER encoding CCS at the old epoch.
                try installWriteKeys()
            case .keysAvailable(let keyBlock, let suite):
                pendingKeyBlock = keyBlock
                negotiatedCipherSuite = suite
            case .expectChangeCipherSpec:
                break // Read keys install on receiving CCS (installReadKeysAndAdvance).
            case .handshakeComplete:
                try finalizeHandshake()
                output.handshakeComplete = true
            }
        }
        if !recordBytes.isEmpty {
            output.datagramsToSend.append(recordBytes)
        }
    }

    /// Installs write keys from the pending key block (client write side).
    private mutating func installWriteKeys() throws(DTLSEngineError) {
        guard let kb = pendingKeyBlock, let suite = negotiatedCipherSuite else {
            throw .internalError(reason: "no pending key block at CCS")
        }
        try record.setWriteKeys(cipherSuite: suite, key: kb.clientWriteKey, fixedIV: kb.clientWriteIV)
    }

    /// Installs read keys from the pending key block (client reads server side).
    private mutating func installReadKeysAndAdvance() throws(DTLSEngineError) {
        guard let kb = pendingKeyBlock, let suite = negotiatedCipherSuite else {
            throw .internalError(reason: "no pending key block at peer CCS")
        }
        try record.setReadKeys(cipherSuite: suite, key: kb.serverWriteKey, fixedIV: kb.serverWriteIV)
    }

    /// Finalizes the handshake: records the peer cert + runs the cert validator.
    private mutating func finalizeHandshake() throws(DTLSEngineError) {
        if remoteCertificateDER == nil, let der = fsm.serverCertificateDER {
            remoteCertificateDER = der
        }
        try runCertificateValidator()
        phase = .connected
    }

    private mutating func runCertificateValidator() throws(DTLSEngineError) {
        guard let validate = configuration.validateCertificate else { return }
        let chain: [[UInt8]] = remoteCertificateDER.map { [$0] } ?? []
        // The core already verified the SKE signature; run the application hook
        // (libp2p PeerID extraction) fail-closed. A throw aborts the handshake.
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
        case .epochMismatch: break // Expected during rekey; not surfaced.
        }
    }
}

// MARK: - Local Span → [UInt8] bulk copy (no Foundation)

extension Span where Element == UInt8 {
    /// Bulk `Span<UInt8>` → `[UInt8]` (one `update(from:)`), Embedded-clean.
    @inline(__always)
    func facadeArrayLocal() -> [UInt8] {
        let n = count
        guard n > 0 else { return [] }
        return [UInt8](unsafeUninitializedCapacity: n) { destination, initializedCount in
            withUnsafeBufferPointer { source in
                destination.baseAddress!.update(from: source.baseAddress!, count: n)
            }
            initializedCount = n
        }
    }
}
