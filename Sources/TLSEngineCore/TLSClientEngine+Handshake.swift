/// `TLSClientEngine` handshake-message dispatch + action translation.
///
/// Mirrors the host `ClientStateMachine` drive logic byte-for-byte, Embedded-clean:
/// it parses each handshake message with the `TLSWireCore` codecs, performs the
/// `TLSConfiguration`-dependent negotiation (cipher suite / group / ALPN / cert
/// type) the cores expect the driver to do, drives the cored FSMs, installs the
/// record protectors as secrets become available, and encrypts the resulting
/// flight at the correct encryption level. X.509 trust + signing are injected.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSHandshakeCore
import TLSRecordCore

extension TLSClientEngine {

    // MARK: - Message dispatch

    mutating func processHandshakeMessage(
        type: HandshakeType,
        content: [UInt8],
        rawMessage: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        switch type {
        case .serverHello:
            try processServerHello(content: content, into: &output)
        case .encryptedExtensions:
            try processEncryptedExtensions(content: content, rawMessage: rawMessage, into: &output)
        case .certificateRequest:
            try processCertificateRequest(content: content, rawMessage: rawMessage, into: &output)
        case .certificate:
            try processCertificate(content: content, rawMessage: rawMessage, into: &output)
        case .certificateVerify:
            try processCertificateVerify(content: content, rawMessage: rawMessage, into: &output)
        case .finished:
            try processServerFinished(content: content, into: &output)
        case .newSessionTicket:
            // Post-handshake resumption tickets are accepted and ignored (no
            // session-cache in the cored engine path); they are not surfaced as
            // application data and never abort the connection.
            break
        case .keyUpdate, .endOfEarlyData, .clientHello, .messageHash:
            throw .protocolFailure(reason: "unexpected handshake message \(type) for client")
        }
    }

    // MARK: - ServerHello

    private mutating func processServerHello(
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard preMachine != nil else {
            throw .protocolFailure(reason: "ServerHello before ClientHello")
        }
        let serverHello: ServerHello
        do {
            serverHello = try ServerHello.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "ServerHello decode failed: \(error)")
        }

        if serverHello.isHelloRetryRequest {
            try processHelloRetryRequest(serverHello, content: content, into: &output)
            return
        }

        // supported_versions must be TLS 1.3.
        guard let sv = serverHello.supportedVersions, sv.isTLS13 else {
            throw .protocolFailure(reason: "ServerHello not TLS 1.3")
        }
        // legacy_session_id_echo must match.
        guard serverHello.legacySessionIDEcho == legacySessionID else {
            throw .protocolFailure(reason: "ServerHello session-id echo mismatch")
        }
        // Cipher suite must be one we offered.
        guard offeredCipherSuites.contains(serverHello.cipherSuite) else {
            throw .protocolFailure(reason: "ServerHello cipher suite not offered")
        }
        if receivedHelloRetryRequest {
            guard serverHello.cipherSuite == negotiatedCipherSuite else {
                throw .protocolFailure(reason: "ServerHello cipher suite differs from HRR")
            }
        }
        negotiatedCipherSuite = serverHello.cipherSuite

        // key_share is required (no PSK-only path in the cored engine).
        guard let serverKeyShare = serverHello.keyShare else {
            throw .protocolFailure(reason: "ServerHello missing key_share")
        }
        guard let keyPair = keyExchange,
              keyPair.group == serverKeyShare.serverShare.group else {
            throw .protocolFailure(reason: "ServerHello key_share group mismatch")
        }

        // Drive the pre-ServerHello core: it performs the downgrade-sentinel check
        // (fail-closed), agrees the (EC)DHE secret, folds SH into the transcript,
        // and derives the handshake-traffic secrets.
        let shMessage = HandshakeCodec.encodeBytes(type: .serverHello, content: content)
        var pre = preMachine!
        let secrets: (client: [UInt8], server: [UInt8])
        do {
            secrets = try pre.ingestServerHello(
                serverRandom: serverHello.random,
                cipherSuite: serverHello.cipherSuite,
                pskAccepted: false,
                keyExchange: .agree(
                    group: keyPair.group,
                    privateKeyBytes: keyPair.privateKeyBytes,
                    peerPublicKeyBytes: serverKeyShare.serverShare.keyExchange
                ),
                rawMessageBytes: shMessage
            )
        } catch {
            preMachine = pre
            throw .from(handshake: error)
        }

        // Install the handshake-level record protectors (client encrypts its
        // flight with its handshake secret; decrypts the server flight with the
        // server handshake secret).
        try installProtectors(
            cipherSuite: serverHello.cipherSuite,
            sendSecret: secrets.client,
            receiveSecret: secrets.server
        )

        // Hand off to the authentication FSM.
        do {
            authMachine = try pre.makeAuthMachine(verifyPeer: configuration.verifyPeer)
        } catch {
            preMachine = pre
            throw .from(handshake: error)
        }
        preMachine = nil
    }

    private mutating func processHelloRetryRequest(
        _ hrr: ServerHello,
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard !receivedHelloRetryRequest else {
            throw .protocolFailure(reason: "second HelloRetryRequest")
        }
        receivedHelloRetryRequest = true

        guard let requestedGroup = hrr.helloRetryRequestSelectedGroup else {
            throw .protocolFailure(reason: "HRR missing key_share group")
        }
        guard configuration.supportedGroups.contains(requestedGroup) else {
            throw .protocolFailure(reason: "HRR selected unsupported group")
        }
        negotiatedCipherSuite = hrr.cipherSuite

        // Apply the RFC 8446 §4.4.1 message_hash transform in the core.
        let hrrMessage = HandshakeCodec.encodeBytes(type: .serverHello, content: content)
        var pre = preMachine!
        do {
            try pre.applyHelloRetryRequest(cipherSuite: hrr.cipherSuite, rawMessageBytes: hrrMessage)
        } catch {
            preMachine = pre
            throw .from(handshake: error)
        }

        // New ephemeral key for the requested group + new ClientHello2.
        let keyPair: TLSKeyExchange<C>.EphemeralKeyPair
        do {
            keyPair = try TLSKeyExchange<C>.generate(for: requestedGroup)
        } catch {
            preMachine = pre
            throw .protocolFailure(reason: "HRR key generation failed: \(error)")
        }
        self.keyExchange = keyPair

        let random = C.random.randomBytes(32)
        let extensions = try buildClientHello2Extensions(keyPair: keyPair)
        let clientHello2: [UInt8]
        do {
            clientHello2 = try pre.produceClientHello2(
                random: random,
                legacySessionID: legacySessionID,
                cipherSuites: offeredCipherSuites,
                extensions: extensions,
                offeredPsks: nil,
                pskBinder: nil
            )
        } catch {
            preMachine = pre
            throw .from(handshake: error)
        }
        preMachine = pre
        output.bytesToSend.append(contentsOf: fragmentPlaintext(type: .handshake, content: clientHello2))
    }

    private func buildClientHello2Extensions(
        keyPair: TLSKeyExchange<C>.EphemeralKeyPair
    ) throws(TLSEngineError) -> [TLSExtension] {
        var extensions: [TLSExtension] = []
        extensions.append(.supportedVersionsClient([TLSConstants.version13]))
        extensions.append(.supportedGroupsList(configuration.supportedGroups))
        extensions.append(.signatureAlgorithmsList(configuration.advertisedSignatureSchemes))
        extensions.append(.keyShareClient([
            KeyShareEntry(group: keyPair.group, keyExchange: keyPair.publicKeyBytes),
        ]))
        if !configuration.alpnProtocols.isEmpty {
            extensions.append(.alpnProtocols(configuration.alpnProtocols))
        }
        if let serverName = configuration.serverName {
            extensions.append(.serverName(ServerNameExtension(hostName: serverName)))
        }
        if let params = configuration.transportParameters, !params.isEmpty {
            extensions.append(.transportParameters(params))
        }
        if configuration.localCertificateTypes != [.x509] {
            extensions.append(.clientCertificateTypes(configuration.localCertificateTypes))
        }
        if configuration.peerCertificateTypes != [.x509] {
            extensions.append(.serverCertificateTypes(configuration.peerCertificateTypes))
        }
        return extensions
    }

    // MARK: - EncryptedExtensions

    private mutating func processEncryptedExtensions(
        content: [UInt8],
        rawMessage: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard authMachine != nil else {
            throw .protocolFailure(reason: "EncryptedExtensions before ServerHello")
        }
        let ee: EncryptedExtensions
        do {
            ee = try EncryptedExtensions.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "EncryptedExtensions decode failed: \(error)")
        }

        // ALPN (RFC 7301 §3.2).
        if let alpn = ee.selectedALPN {
            guard !configuration.alpnProtocols.isEmpty else {
                throw .protocolFailure(reason: "server sent ALPN but client offered none")
            }
            guard configuration.alpnProtocols.contains(alpn) else {
                throw .protocolFailure(reason: "server selected ALPN not offered")
            }
            negotiatedALPNValue = alpn
        }

        if let params = ee.transportParameters {
            peerTransportParameters = params
        }

        // RFC 7250 server_certificate_type negotiation.
        if let selected = ee.selectedServerCertificateType {
            guard configuration.peerCertificateTypes != [.x509] else {
                throw .protocolFailure(reason: "server sent server_certificate_type unoffered")
            }
            guard configuration.peerCertificateTypes.contains(selected) else {
                throw .protocolFailure(reason: "server selected unsupported server cert type")
            }
        } else if !configuration.peerCertificateTypes.contains(.x509) {
            throw .protocolFailure(reason: "server did not select raw_public_key and X.509 disabled")
        }
        if let selected = ee.selectedClientCertificateType {
            guard configuration.localCertificateTypes != [.x509] else {
                throw .protocolFailure(reason: "server sent client_certificate_type unoffered")
            }
            guard configuration.localCertificateTypes.contains(selected) else {
                throw .protocolFailure(reason: "server selected unsupported client cert type")
            }
        }

        let earlyDataAccepted = ee.extensions.contains { $0.extensionType == .earlyData }

        let eeMessage = HandshakeCodec.encodeBytes(type: .encryptedExtensions, content: content)
        var auth = authMachine!
        let actions: [TLSHandshakeAction]
        do {
            actions = try auth.ingestEncryptedExtensions(
                rawMessageBytes: eeMessage,
                earlyDataAccepted: earlyDataAccepted
            )
        } catch {
            authMachine = auth
            throw .from(handshake: error)
        }
        authMachine = auth
        try applyActions(actions, into: &output)
    }

    // MARK: - CertificateRequest

    private mutating func processCertificateRequest(
        content: [UInt8],
        rawMessage: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard authMachine != nil else {
            throw .protocolFailure(reason: "CertificateRequest before ServerHello")
        }
        let request: CertificateRequest
        do {
            request = try CertificateRequest.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "CertificateRequest decode failed: \(error)")
        }
        clientCertificateRequested = true

        let message = HandshakeCodec.encodeBytes(type: .certificateRequest, content: content)
        var auth = authMachine!
        let actions: [TLSHandshakeAction]
        do {
            actions = try auth.ingestCertificateRequest(request, rawMessageBytes: message)
        } catch {
            authMachine = auth
            throw .from(handshake: error)
        }
        authMachine = auth
        try applyActions(actions, into: &output)
    }

    // MARK: - Certificate

    private mutating func processCertificate(
        content: [UInt8],
        rawMessage: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard authMachine != nil else {
            throw .protocolFailure(reason: "Certificate before ServerHello")
        }
        let certificate: Certificate
        do {
            certificate = try Certificate.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "Certificate decode failed: \(error)")
        }
        setPeerCertificates(certificate.certificates)

        let message = HandshakeCodec.encodeBytes(type: .certificate, content: content)
        var auth = authMachine!
        let actions: [TLSHandshakeAction]
        do {
            actions = try auth.ingestServerCertificate(
                certificatePresented: !certificate.certificates.isEmpty,
                rawMessageBytes: message
            )
        } catch {
            authMachine = auth
            throw .from(handshake: error)
        }
        authMachine = auth
        try applyActions(actions, into: &output)
    }

    // MARK: - CertificateVerify

    private mutating func processCertificateVerify(
        content: [UInt8],
        rawMessage: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard authMachine != nil else {
            throw .protocolFailure(reason: "CertificateVerify before ServerHello")
        }
        let cv: CertificateVerify
        do {
            cv = try CertificateVerify.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "CertificateVerify decode failed: \(error)")
        }

        // Adapter-side peer-key resolution (X.509 stays OUT of the engine): the
        // injected `resolvePeerKey` closure produces the verification key from the
        // peer certificate-list DER. The core enforces the scheme/algorithm match
        // and the proof-of-possession signature, fail-closed.
        let peerKey = configuration.resolvePeerKey?(currentPeerCertificateListDER())

        let message = HandshakeCodec.encodeBytes(type: .certificateVerify, content: content)
        var auth = authMachine!
        let actions: [TLSHandshakeAction]
        do {
            actions = try auth.ingestServerCertificateVerify(
                cv,
                peerPublicKey: peerKey,
                rawMessageBytes: message
            )
        } catch {
            authMachine = auth
            throw .from(handshake: error)
        }
        authMachine = auth
        try applyActions(actions, into: &output)
    }

    // MARK: - Server Finished + client flight

    private mutating func processServerFinished(
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard authMachine != nil else {
            throw .protocolFailure(reason: "Finished before ServerHello")
        }
        let finished: Finished
        do {
            finished = try Finished.decode(from: content, hashLength: negotiatedCipherSuite.hashLength)
        } catch {
            throw .protocolFailure(reason: "Finished decode failed: \(error)")
        }

        var auth = authMachine!

        // Verify server Finished MAC, derive secrets, emit any EndOfEarlyData.
        let eoedActions: [TLSHandshakeAction]
        do {
            eoedActions = try auth.ingestServerFinished(finished)
        } catch {
            authMachine = auth
            throw .from(handshake: error)
        }
        try applyActions(eoedActions, into: &output)

        // Client mTLS flight (signing injected). `buildClientCertificateFlight`
        // is typed `throws(TLSEngineError)`, so a bare `catch` binds the engine
        // error directly (no `as` pattern — those crash SILGen under Embedded).
        if clientCertificateRequested {
            do {
                try buildClientCertificateFlight(auth: &auth)
            } catch {
                authMachine = auth
                throw error
            }
        }

        let finalActions: [TLSHandshakeAction]
        do {
            finalActions = try auth.finalizeClientFlight(alpn: negotiatedALPNValue)
        } catch {
            authMachine = auth
            throw .from(handshake: error)
        }
        authMachine = auth
        try applyActions(finalActions, into: &output)
    }

    /// Builds the client Certificate (+ CertificateVerify), signing via the
    /// injected signer. Mirrors `ClientStateMachine.buildClientCertificateFlight`:
    /// Certificate is always sent (empty when no material); CertificateVerify
    /// follows only when a signer and a non-empty payload are present.
    ///
    /// Typed throws (`TLSEngineError`) with bare `catch { }` (the generic
    /// typed-throws helper + `catch as E` crash SILGen under Embedded).
    private mutating func buildClientCertificateFlight(
        auth: inout TLSClientAuthMachine<C>
    ) throws(TLSEngineError) {
        let chain = configuration.certificateChain ?? []
        let haveMaterial = configuration.sign != nil
            && configuration.signingScheme != nil
            && !chain.isEmpty

        if haveMaterial, let signingScheme = configuration.signingScheme, let sign = configuration.sign {
            let certificate = Certificate(certificateRequestContext: [], certificates: chain)
            let certMessage: [UInt8]
            do { certMessage = try certificate.encodeAsHandshakeBytes() }
            catch { throw .protocolFailure(reason: "client Certificate encode failed: \(error)") }
            let transcriptForCV: [UInt8]
            do { transcriptForCV = try auth.foldClientCertificate(messageBytes: certMessage) }
            catch { throw .from(handshake: error) }

            let signedContent = CertificateVerify.constructSignatureContentBytes(
                transcriptHash: transcriptForCV,
                isServer: false
            )
            // The injected signer is typed `throws(TLSEngineError)`; propagate.
            let signature = try sign(signedContent, signingScheme)
            let cv = CertificateVerify(algorithm: signingScheme, signature: signature)
            let cvMessage: [UInt8]
            do { cvMessage = try cv.encodeAsHandshakeBytes() }
            catch { throw .protocolFailure(reason: "client CertificateVerify encode failed: \(error)") }
            do { try auth.foldClientCertificateVerify(messageBytes: cvMessage) }
            catch { throw .from(handshake: error) }
        } else {
            // No material — send an empty Certificate, no CertificateVerify.
            let empty = Certificate(certificateRequestContext: [], certificates: [])
            let certMessage: [UInt8]
            do { certMessage = try empty.encodeAsHandshakeBytes() }
            catch { throw .protocolFailure(reason: "empty Certificate encode failed: \(error)") }
            do { _ = try auth.foldClientCertificate(messageBytes: certMessage) }
            catch { throw .from(handshake: error) }
        }
    }

    // MARK: - Action translation (encrypt at level + install keys + validate cert)

    mutating func applyActions(
        _ actions: [TLSHandshakeAction],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        for action in actions {
            switch action {
            case .send(let bytes, let level):
                try emit(bytes: bytes, level: level, into: &output)
            case .secretsAvailable(let secrets):
                try installSecretsAvailable(secrets)
            case .earlyDataEnd:
                // The cored engine does not negotiate 0-RTT; nothing to discard.
                break
            case .runCertificateValidator:
                try runCertificateValidator()
            case .handshakeComplete(let alpn, _):
                if let alpn { negotiatedALPNValue = alpn }
                markConnected()
                output.handshakeComplete = true
            }
        }
    }

    /// Encrypts (if a send protector is active) and frames a flight at `level`.
    private mutating func emit(
        bytes: [UInt8],
        level: TLSHandshakeLevel,
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        if level == .initial {
            output.bytesToSend.append(contentsOf: fragmentPlaintext(type: .handshake, content: bytes))
            return
        }
        // .earlyData and .handshake/.application are all encrypted with the active
        // send protector (the cored engine has no separate 0-RTT cryptor).
        guard sendProtector != nil else {
            throw .internalError(reason: "no send protector for level \(level)")
        }
        output.bytesToSend.append(contentsOf: try encryptAndFrame(content: bytes, type: .handshake))
    }

    /// Installs record protectors when application secrets become available.
    private mutating func installSecretsAvailable(
        _ secrets: TLSHandshakeSecrets
    ) throws(TLSEngineError) {
        // The client receives `.application` secrets in `finalizeClientFlight`.
        // Handshake secrets are installed directly in `processServerHello`.
        guard secrets.level == .application else { return }
        try installProtectors(
            cipherSuite: secrets.cipherSuite,
            sendSecret: secrets.client,
            receiveSecret: secrets.server
        )
    }

    private mutating func runCertificateValidator() throws(TLSEngineError) {
        guard let validate = configuration.validateCertificate else { return }
        let chain = currentPeerCertificateListDER()
        // Mirror the legacy gate: only validate when verifyPeer OR a cert was
        // presented (the core already ran the proof-of-possession check).
        guard configuration.verifyPeer || !chain.isEmpty else { return }
        // The injected validator is typed `throws(TLSEngineError)`; its failure
        // (X.509 / user-hook) propagates directly, fail-closed.
        try validate(chain)
    }
}
