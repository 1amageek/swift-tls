/// `TLSServerEngine` handshake dispatch + ClientHello → server-flight orchestration.
///
/// Mirrors the host `ServerStateMachine` drive logic byte-for-byte, Embedded-clean:
/// it parses the ClientHello, performs the `TLSConfiguration`-dependent negotiation
/// (cipher suite / group / ALPN / cert type), generates the server (EC)DHE share
/// through the `CryptoProvider` seam, assembles the ServerHello / EncryptedExtensions /
/// CertificateRequest / Certificate wire bytes, drives the cored
/// ``TLSServerHandshake`` (which folds the transcript, derives secrets, and verifies
/// the client CertificateVerify + Finished, fail-closed), and installs the record
/// protectors with the correct receive-key deferral. Signing + X.509 trust injected.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSHandshakeCore
import TLSRecordCore

extension TLSServerEngine {

    // MARK: - Dispatch

    mutating func processHandshakeMessage(
        type: HandshakeType,
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        switch type {
        case .clientHello:
            try processClientHello(content: content, into: &output)
        case .certificate:
            try processClientCertificate(content: content, into: &output)
        case .certificateVerify:
            try processClientCertificateVerify(content: content, into: &output)
        case .finished:
            try processClientFinished(content: content, into: &output)
        case .endOfEarlyData:
            // 0-RTT is not negotiated by the cored server engine; reject.
            throw .protocolFailure(reason: "unexpected EndOfEarlyData")
        case .serverHello, .encryptedExtensions, .certificateRequest,
             .newSessionTicket, .keyUpdate, .messageHash:
            throw .protocolFailure(reason: "unexpected handshake message \(type) for server")
        }
    }

    // MARK: - ClientHello → server flight

    private mutating func processClientHello(
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        let isClientHello2 = (phase == .sentHelloRetryRequest)
        guard phase == .start || isClientHello2 else {
            throw .protocolFailure(reason: "unexpected ClientHello in state \(phase)")
        }
        if serverMachine == nil {
            serverMachine = TLSServerHandshake<C>()
        }

        let clientHello: ClientHello
        do {
            clientHello = try ClientHello.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "ClientHello decode failed: \(error)")
        }

        // The cored server engine does not accept PSK resumption (no ticket store).
        // pre_shared_key, if present, must still be last (RFC 8446 §4.2.11), but it
        // is not honoured — the handshake proceeds as a full (EC)DHE handshake.
        guard let supportedVersions = clientHello.supportedVersions, supportedVersions.supportsTLS13 else {
            throw .protocolFailure(reason: "ClientHello not TLS 1.3")
        }

        // Cipher suite (server preference order).
        guard let selectedSuite = configuration.supportedCipherSuites.first(where: {
            clientHello.cipherSuites.contains($0)
        }) else {
            throw .protocolFailure(reason: "no common cipher suite")
        }
        if isClientHello2 {
            guard selectedSuite == negotiatedCipherSuite else {
                throw .protocolFailure(reason: "ClientHello2 cipher suite inconsistent with HRR")
            }
        }
        negotiatedCipherSuite = selectedSuite

        // Client's signature_algorithms (validated against server CertificateVerify).
        for ext in clientHello.extensions {
            if case .signatureAlgorithms(let sigAlgs) = ext {
                clientSignatureAlgorithms = sigAlgs.supportedSignatureAlgorithms
                break
            }
        }

        // key_share negotiation.
        guard let clientKeyShare = clientHello.keyShare else {
            throw .protocolFailure(reason: "ClientHello missing key_share")
        }
        var selectedGroup: NamedGroup?
        var peerShare: KeyShareEntry?
        if isClientHello2 {
            guard let requested = helloRetryRequestGroup,
                  let entry = clientKeyShare.keyShare(for: requested) else {
                throw .protocolFailure(reason: "ClientHello2 missing requested key_share group")
            }
            selectedGroup = requested
            peerShare = entry
        } else {
            for group in configuration.supportedGroups {
                if let entry = clientKeyShare.keyShare(for: group) {
                    selectedGroup = group
                    peerShare = entry
                    break
                }
            }
            if selectedGroup == nil {
                // Try a HelloRetryRequest for a group the client supports but did
                // not key-share (RFC 8446 §4.1.4).
                let clientGroups = clientHello.supportedGroups?.namedGroups ?? []
                let clientShareGroups = clientKeyShare.clientShares.map { $0.group }
                if let common = configuration.supportedGroups.first(where: {
                    clientGroups.contains($0) && !clientShareGroups.contains($0)
                        && TLSKeyExchange<C>.publicKeyLength(for: $0) != nil
                }) {
                    try sendHelloRetryRequest(
                        clientHello: clientHello, content: content, requestedGroup: common, into: &output
                    )
                    return
                }
                throw .protocolFailure(reason: "no key_share match")
            }
        }
        guard let selectedGroup, let peerShare else {
            throw .protocolFailure(reason: "no key_share match")
        }

        if let params = clientHello.transportParameters {
            peerTransportParameters = params
        }

        // Server (EC)DHE share + shared secret through the seam.
        let serverKeyPair: TLSKeyExchange<C>.EphemeralKeyPair
        do {
            serverKeyPair = try TLSKeyExchange<C>.generate(for: selectedGroup)
        } catch {
            throw .protocolFailure(reason: "server key generation failed: \(error)")
        }
        let sharedSecret: [UInt8]
        do {
            sharedSecret = try TLSKeyExchange<C>.sharedSecret(
                group: selectedGroup,
                privateKeyBytes: serverKeyPair.privateKeyBytes.span,
                peerPublicKeyBytes: peerShare.keyExchange.span
            )
        } catch {
            throw .protocolFailure(reason: "(EC)DHE failed: \(error)")
        }

        // ALPN (RFC 7301 §3.2).
        if let clientALPN = clientHello.alpn {
            if !configuration.alpnProtocols.isEmpty {
                guard let common = ALPNExtension(protocols: configuration.alpnProtocols)
                    .negotiate(with: clientALPN) else {
                    throw .protocolFailure(reason: "no ALPN match")
                }
                negotiatedALPNValue = common
            }
        } else if !configuration.alpnProtocols.isEmpty {
            throw .protocolFailure(reason: "client offered no ALPN but server requires it")
        }

        // Certificate-type negotiation (RFC 7250).
        let willRequestClientCert = configuration.requireClientCertificate
        var echoServerCertType = false
        var echoClientCertType = false
        if let offered = clientHello.serverCertificateTypes {
            guard let selected = configuration.localCertificateTypes.first(where: { offered.contains($0) }) else {
                throw .protocolFailure(reason: "no common server certificate type")
            }
            negotiatedServerCertType = selected
            echoServerCertType = true
        } else if !configuration.localCertificateTypes.contains(.x509) {
            throw .protocolFailure(reason: "client did not offer raw_public_key for server cert")
        }
        if willRequestClientCert {
            if let offered = clientHello.clientCertificateTypes {
                guard let selected = configuration.peerCertificateTypes.first(where: { offered.contains($0) }) else {
                    throw .protocolFailure(reason: "no common client certificate type")
                }
                negotiatedClientCertType = selected
                echoClientCertType = true
            } else if !configuration.peerCertificateTypes.contains(.x509) {
                throw .protocolFailure(reason: "client did not offer raw_public_key for client cert")
            }
        }

        try buildAndEmitServerFlight(
            clientHelloContent: content,
            selectedSuite: selectedSuite,
            selectedGroup: selectedGroup,
            serverShare: serverKeyPair.publicKeyBytes,
            sharedSecret: sharedSecret,
            sessionIDEcho: clientHello.legacySessionID,
            willRequestClientCert: willRequestClientCert,
            echoServerCertType: echoServerCertType,
            echoClientCertType: echoClientCertType,
            into: &output
        )
    }

    // swiftlint:disable:next function_body_length
    private mutating func buildAndEmitServerFlight(
        clientHelloContent: [UInt8],
        selectedSuite: CipherSuite,
        selectedGroup: NamedGroup,
        serverShare: [UInt8],
        sharedSecret: [UInt8],
        sessionIDEcho: [UInt8],
        willRequestClientCert: Bool,
        echoServerCertType: Bool,
        echoClientCertType: Bool,
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        let clientHelloMessage = HandshakeCodec.encodeBytes(type: .clientHello, content: clientHelloContent)

        // ServerHello.
        let shExtensions: [TLSExtension] = [
            .supportedVersionsServer(TLSConstants.version13),
            .keyShareServer(KeyShareEntry(group: selectedGroup, keyExchange: serverShare)),
        ]
        let serverHelloMessage: [UInt8]
        do {
            let sh = try ServerHello(
                random: C.random.randomBytes(32),
                legacySessionIDEcho: sessionIDEcho,
                cipherSuite: selectedSuite,
                extensions: shExtensions
            )
            serverHelloMessage = try sh.encodeAsHandshakeBytes()
        } catch {
            throw .protocolFailure(reason: "ServerHello encode failed: \(error)")
        }

        // EncryptedExtensions.
        var eeExtensions: [TLSExtension] = []
        if let alpn = negotiatedALPNValue {
            eeExtensions.append(.alpn(ALPNExtension(protocols: [alpn])))
        }
        if let params = configuration.transportParameters, !params.isEmpty {
            eeExtensions.append(.transportParameters(params))
        }
        if echoServerCertType {
            eeExtensions.append(.serverCertificateTypeSelected(negotiatedServerCertType))
        }
        if echoClientCertType {
            eeExtensions.append(.clientCertificateTypeSelected(negotiatedClientCertType))
        }
        let eeMessage: [UInt8]
        do {
            eeMessage = try EncryptedExtensions(extensions: eeExtensions).encodeAsHandshakeBytes()
        } catch {
            throw .protocolFailure(reason: "EncryptedExtensions encode failed: \(error)")
        }

        // CertificateRequest (mutual TLS).
        var certRequestMessage: [UInt8]?
        var crSignatureAlgorithms: [TLSWireCore.SignatureScheme]?
        if willRequestClientCert {
            let cr = CertificateRequest.withDefaultSignatureAlgorithms()
            do {
                certRequestMessage = try cr.encodeAsHandshakeBytes()
            } catch {
                throw .protocolFailure(reason: "CertificateRequest encode failed: \(error)")
            }
            certificateRequestContext = cr.certificateRequestContext
            crSignatureAlgorithms = cr.signatureAlgorithms
            requestedClientCertificate = true
        }

        // Server Certificate (always non-PSK).
        guard let signingScheme = configuration.signingScheme, let sign = configuration.sign else {
            throw .invalidConfiguration(reason: "server requires a signing identity")
        }
        let serverCertificates: [[UInt8]]
        switch negotiatedServerCertType {
        case .rawPublicKey:
            guard let chain = configuration.certificateChain, let spki = chain.first else {
                throw .invalidConfiguration(reason: "server raw_public_key requires SubjectPublicKeyInfo")
            }
            serverCertificates = [spki]
        case .x509:
            guard let chain = configuration.certificateChain, !chain.isEmpty else {
                throw .invalidConfiguration(reason: "server X.509 requires a certificate chain")
            }
            serverCertificates = chain
        }
        let serverCertMessage: [UInt8]
        do {
            serverCertMessage = try Certificate(certificates: serverCertificates).encodeAsHandshakeBytes()
        } catch {
            throw .protocolFailure(reason: "server Certificate encode failed: \(error)")
        }
        // RFC 8446 §4.4.3: the server CertificateVerify scheme must be one the
        // client offered.
        if let clientOffered = clientSignatureAlgorithms {
            guard clientOffered.contains(signingScheme) else {
                throw .verificationFailed(reason: "server signing scheme not offered by client")
            }
        }

        var machine = serverMachine!
        let parameters = TLSServerHandshake<C>.FlightParameters(
            cipherSuite: selectedSuite,
            acceptedPSK: nil,
            keyExchange: .precomputed(sharedSecret),
            earlyDataAccepted: false,
            requestClientCertificate: willRequestClientCert,
            certificateRequestSignatureAlgorithms: crSignatureAlgorithms
        )
        let flight: (
            handshakeSecrets: (client: [UInt8], server: [UInt8]),
            clientEarlyTrafficSecret: [UInt8]?,
            certificateVerifyRequest: TLSServerHandshake<C>.ServerCertificateVerifyRequest?
        )
        do {
            flight = try machine.beginServerFlight(
                clientHelloBytes: clientHelloMessage,
                parameters: parameters,
                serverHelloBytes: serverHelloMessage,
                encryptedExtensionsBytes: eeMessage,
                certificateRequestBytes: certRequestMessage,
                serverCertificateBytes: serverCertMessage
            )
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }

        // Install handshake-level protectors: server sends with its handshake
        // secret, receives the client flight with the CLIENT handshake secret.
        do {
            try installProtectors(
                cipherSuite: selectedSuite,
                sendSecret: flight.handshakeSecrets.server,
                receiveSecret: flight.handshakeSecrets.client
            )
        } catch {
            serverMachine = machine
            throw error
        }

        // ServerHello goes out as a plaintext record; the rest is encrypted with
        // the server handshake secret.
        output.bytesToSend.append(contentsOf: fragmentPlaintext(type: .handshake, content: serverHelloMessage))

        // Sign + fold the server CertificateVerify.
        guard let cvRequest = flight.certificateVerifyRequest else {
            serverMachine = machine
            throw .internalError(reason: "missing CertificateVerify request")
        }
        let signedContent = CertificateVerify.constructSignatureContentBytes(
            transcriptHash: cvRequest.transcriptHash,
            isServer: true
        )
        let signature = try sign(signedContent, signingScheme)
        let cvMessage: [UInt8]
        do {
            cvMessage = try CertificateVerify(algorithm: signingScheme, signature: signature).encodeAsHandshakeBytes()
        } catch {
            serverMachine = machine
            throw .protocolFailure(reason: "server CertificateVerify encode failed: \(error)")
        }
        do {
            try machine.foldServerCertificateVerify(messageBytes: cvMessage)
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }

        // Server Finished + application secrets.
        let finish: (serverFinished: [UInt8], applicationSecrets: (client: [UInt8], server: [UInt8]), exporterMasterSecret: [UInt8])
        do {
            finish = try machine.finishServerFlight()
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }
        serverMachine = machine

        // Assemble the encrypted handshake flight (EE, CR?, Cert, CertVerify, Finished),
        // all encrypted with the server handshake secret in transcript order.
        var flightBytes: [UInt8] = []
        flightBytes.append(contentsOf: eeMessage)
        if let cr = certRequestMessage { flightBytes.append(contentsOf: cr) }
        flightBytes.append(contentsOf: serverCertMessage)
        flightBytes.append(contentsOf: cvMessage)
        flightBytes.append(contentsOf: finish.serverFinished)
        output.bytesToSend.append(contentsOf: try encryptAndFrame(content: flightBytes, type: .handshake))

        // Switch the SEND protector to the server application secret immediately;
        // DEFER the receive switch to the client application secret until the
        // client Finished is verified (RFC 8446 server key schedule).
        do {
            try installProtectors(
                cipherSuite: selectedSuite,
                sendSecret: finish.applicationSecrets.server,
                receiveSecret: nil
            )
        } catch {
            throw error
        }
        pendingClientApplicationSecret = finish.applicationSecrets.client

        phase = willRequestClientCert ? .waitClientCertificate : .waitFinished
    }

    private mutating func sendHelloRetryRequest(
        clientHello: ClientHello,
        content: [UInt8],
        requestedGroup: NamedGroup,
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard !sentHelloRetryRequest else {
            throw .protocolFailure(reason: "multiple HelloRetryRequest not allowed")
        }
        sentHelloRetryRequest = true
        helloRetryRequestGroup = requestedGroup

        let clientHelloMessage = HandshakeCodec.encodeBytes(type: .clientHello, content: content)
        let hrrMessage: [UInt8]
        do {
            let hrr = try ServerHello.helloRetryRequest(
                legacySessionIDEcho: clientHello.legacySessionID,
                cipherSuite: negotiatedCipherSuite,
                extensions: [
                    .supportedVersionsServer(TLSConstants.version13),
                    .keyShare(.helloRetryRequest(KeyShareHelloRetryRequest(selectedGroup: requestedGroup))),
                ]
            )
            hrrMessage = try hrr.encodeAsHandshakeBytes()
        } catch {
            throw .protocolFailure(reason: "HelloRetryRequest encode failed: \(error)")
        }

        var machine = serverMachine!
        do {
            try machine.applyHelloRetryRequest(
                cipherSuite: negotiatedCipherSuite,
                clientHello1Bytes: clientHelloMessage,
                helloRetryRequestBytes: hrrMessage
            )
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }
        serverMachine = machine

        phase = .sentHelloRetryRequest
        output.bytesToSend.append(contentsOf: fragmentPlaintext(type: .handshake, content: hrrMessage))
    }

    // MARK: - Client flight (mutual TLS)

    private mutating func processClientCertificate(
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard phase == .waitClientCertificate else {
            throw .protocolFailure(reason: "unexpected client Certificate")
        }
        let certificate: Certificate
        do {
            certificate = try Certificate.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "client Certificate decode failed: \(error)")
        }
        guard certificate.certificateRequestContext == certificateRequestContext else {
            throw .protocolFailure(reason: "client certificate_request_context mismatch")
        }

        var machine = serverMachine!
        let message = HandshakeCodec.encodeBytes(type: .certificate, content: content)

        if certificate.certificates.isEmpty {
            // Empty client certificate: fail if we require client auth.
            if configuration.requireClientCertificate {
                throw .verificationFailed(reason: "client certificate required but none presented")
            }
            do {
                _ = try machine.ingestClientCertificate(certificatePresented: false, rawMessageBytes: message)
            } catch {
                serverMachine = machine
                throw .from(handshake: error)
            }
            serverMachine = machine
            phase = .waitFinished
            return
        }

        setClientCertificates(certificate.certificates)
        // Resolve the client verification key adapter-side (X.509 stays OUT).
        clientHelloPeerKey = configuration.resolvePeerKey?(certificate.certificates)

        do {
            _ = try machine.ingestClientCertificate(certificatePresented: true, rawMessageBytes: message)
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }
        serverMachine = machine
        phase = .waitClientCertificateVerify
    }

    private mutating func processClientCertificateVerify(
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard phase == .waitClientCertificateVerify else {
            throw .protocolFailure(reason: "unexpected client CertificateVerify")
        }
        let cv: CertificateVerify
        do {
            cv = try CertificateVerify.decode(from: content)
        } catch {
            throw .protocolFailure(reason: "client CertificateVerify decode failed: \(error)")
        }

        var machine = serverMachine!
        let message = HandshakeCodec.encodeBytes(type: .certificateVerify, content: content)
        do {
            try machine.ingestClientCertificateVerify(
                cv,
                clientPublicKey: clientHelloPeerKey,
                rawMessageBytes: message
            )
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }
        serverMachine = machine

        // Run the injected validation strategy (X.509 chain / user-hook) AFTER the
        // in-core proof-of-possession signature check, fail-closed. Its returned
        // identifier (e.g. the libp2p PeerID) is recorded for `peerIdentifier`.
        if let validate = configuration.validateCertificate {
            let chain = currentClientCertificateListDER()
            if configuration.verifyPeer || !chain.isEmpty {
                validatedPeerIdentifier = try validate(chain)
            }
        }

        phase = .waitFinished
    }

    private mutating func processClientFinished(
        content: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        guard phase == .waitFinished else {
            throw .protocolFailure(reason: "unexpected client Finished")
        }
        let finished: Finished
        do {
            finished = try Finished.decode(from: content, hashLength: negotiatedCipherSuite.hashLength)
        } catch {
            throw .protocolFailure(reason: "client Finished decode failed: \(error)")
        }

        var machine = serverMachine!
        do {
            try machine.ingestClientFinished(finished)
        } catch {
            serverMachine = machine
            throw .from(handshake: error)
        }
        serverMachine = machine

        // Now that the client Finished is verified, switch the receive protector to
        // the client application secret (the deferred key install).
        guard let clientAppSecret = pendingClientApplicationSecret else {
            throw .internalError(reason: "missing deferred client application secret")
        }
        do {
            try installProtectors(
                cipherSuite: negotiatedCipherSuite,
                sendSecret: nil,
                receiveSecret: clientAppSecret
            )
        } catch {
            throw error
        }
        pendingClientApplicationSecret = nil

        markConnected()
        output.handshakeComplete = true
    }
}
