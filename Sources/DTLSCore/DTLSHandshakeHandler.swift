/// DTLS 1.2 Handshake Handler
///
/// Integrates state machine, message encoding/decoding, key exchange, and
/// key schedule into a unified handshake processor.
///
/// DTLS 1.2 Full Handshake Flow:
///   Flight 1: Client → ClientHello
///   Flight 2: Server → HelloVerifyRequest
///   Flight 3: Client → ClientHello (with cookie)
///   Flight 4: Server → ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
///   Flight 5: Client → Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished
///   Flight 6: Server → CCS, Finished

import Foundation
import Crypto
import Synchronization
import TLSCore

// MARK: - Legacy Result Type

/// Result of processing handshake data
///
/// Retained for backward compatibility. New code should use `[DTLSHandshakeAction]`.
public struct DTLSHandshakeResult: Sendable {
    /// Messages to send to the peer
    public let outputMessages: [Data]

    /// Whether the handshake is complete
    public let isComplete: Bool

    /// Derived key block (available when handshake completes)
    public let keyBlock: DTLSKeyBlock?

    /// The negotiated cipher suite
    public let cipherSuite: DTLSCipherSuite?

    public init(
        outputMessages: [Data] = [],
        isComplete: Bool = false,
        keyBlock: DTLSKeyBlock? = nil,
        cipherSuite: DTLSCipherSuite? = nil
    ) {
        self.outputMessages = outputMessages
        self.isComplete = isComplete
        self.keyBlock = keyBlock
        self.cipherSuite = cipherSuite
    }
}

// MARK: - Client Handshake Handler

/// DTLS 1.2 handshake handler for the client side
public final class DTLSClientHandshakeHandler: Sendable {
    private let handlerState: Mutex<HandlerState>
    private let certificate: DTLSCertificate
    private let supportedCipherSuites: [DTLSCipherSuite]

    private struct HandlerState: Sendable {
        var state: DTLSClientState = .idle
        var context: DTLSClientContext = DTLSClientContext()
    }

    public init(
        certificate: DTLSCertificate,
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256]
    ) {
        self.certificate = certificate
        self.supportedCipherSuites = supportedCipherSuites
        self.handlerState = Mutex(HandlerState())
    }

    /// Start the handshake by generating the initial ClientHello
    /// - Throws: A secure-random error if the system CSPRNG fails while generating
    ///   the ClientHello random. RNG failure is surfaced, never swallowed.
    public func startHandshake() throws -> [DTLSHandshakeAction] {
        try handlerState.withLock { s in
            let clientHello = try DTLSClientHello(
                cipherSuites: supportedCipherSuites
            )
            s.context.clientRandom = clientHello.random

            let body = clientHello.encode()
            let msg = DTLSHandshakeHeader.encodeMessage(
                type: .clientHello,
                messageSeq: s.context.nextMessageSeq(),
                body: body
            )
            s.context.handshakeMessages.append(msg)

            s.state = .waitingServerHello
            return [.sendMessage(msg)]
        }
    }

    /// Process a received handshake message
    ///
    /// Takes the raw handshake message bytes (header + body) to correctly
    /// record in the transcript hash. This fixes the bug where server messages
    /// were not being recorded in the client's transcript.
    ///
    /// - Parameter rawMessage: Complete handshake message (12-byte DTLS header + body)
    /// - Returns: Actions for DTLSConnection to execute
    public func processHandshakeMessage(_ rawMessage: Data) throws -> [DTLSHandshakeAction] {
        try handlerState.withLock { s in
            var reader = TLSReader(data: rawMessage)
            let header = try DTLSHandshakeHeader.decode(reader: &reader)
            let body = Data(try reader.readBytes(Int(header.fragmentLength)))

            // RFC 6347 §4.2.2: order/dedup on message_seq BEFORE touching the
            // transcript. A duplicate (seq < expected) is silently discarded so a
            // retransmission cannot be re-appended to the transcript; a future seq
            // (seq > expected) is rejected (retransmission will re-deliver in order).
            switch try Self.classifyReceiveSeq(header.messageSeq, expected: s.context.nextReceiveSeq) {
            case .duplicate:
                return []
            case .inOrder:
                s.context.nextReceiveSeq = header.messageSeq &+ 1
            }

            // Record in transcript:
            // - HelloVerifyRequest: excluded per RFC 6347 Section 4.2.1
            // - Finished: excluded until after verification (hash must not include itself)
            if header.messageType != .helloVerifyRequest && header.messageType != .finished {
                s.context.handshakeMessages.append(rawMessage)
            }

            switch (s.state, header.messageType) {
            case (.waitingServerHello, .helloVerifyRequest):
                return try handleHelloVerifyRequest(body, state: &s)

            case (.waitingServerHello, .serverHello),
                 (.waitingServerHelloWithCookie, .serverHello):
                try handleServerHello(body, state: &s)
                s.state = .waitingCertificate
                return []

            case (.waitingCertificate, .certificate):
                try handleCertificate(body, state: &s)
                s.state = .waitingServerKeyExchange
                return []

            case (.waitingServerKeyExchange, .serverKeyExchange):
                try handleServerKeyExchange(body, state: &s)
                s.state = .waitingServerHelloDone
                return []

            case (.waitingServerHelloDone, .serverHelloDone):
                return try handleServerHelloDone(body, state: &s)

            case (.waitingFinished, .finished):
                return try handleServerFinished(body, rawMessage: rawMessage, state: &s)

            default:
                throw DTLSError.unexpectedMessage(
                    expected: expectedType(for: s.state),
                    received: header.messageType
                )
            }
        }
    }

    /// Process a ChangeCipherSpec record (not a handshake message)
    public func processChangeCipherSpec() throws {
        try handlerState.withLock { s in
            guard s.state == .waitingChangeCipherSpec else {
                throw DTLSError.invalidState("Unexpected ChangeCipherSpec in state: \(s.state)")
            }
            s.state = .waitingFinished
        }
    }

    // MARK: - Accessors

    /// Whether the handshake is complete
    public var isComplete: Bool {
        handlerState.withLock { $0.state == .connected }
    }

    /// The current handshake state
    public var currentState: DTLSClientState {
        handlerState.withLock { $0.state }
    }

    /// The server's DER-encoded certificate (available after Certificate message)
    public var serverCertificateDER: Data? {
        handlerState.withLock { $0.context.serverCertificateDER }
    }

    /// The negotiated cipher suite (available after ServerHello)
    public var negotiatedCipherSuite: DTLSCipherSuite? {
        handlerState.withLock { $0.context.cipherSuite }
    }

    /// The next handshake message_seq this handler expects to receive from the
    /// peer (used for in-order processing and duplicate rejection).
    public var nextExpectedReceiveSeq: UInt16 {
        handlerState.withLock { $0.context.nextReceiveSeq }
    }

    // MARK: - Private Handlers

    private func expectedType(for state: DTLSClientState) -> DTLSHandshakeType {
        switch state {
        case .waitingServerHello, .waitingServerHelloWithCookie: return .serverHello
        case .waitingCertificate: return .certificate
        case .waitingServerKeyExchange: return .serverKeyExchange
        case .waitingServerHelloDone: return .serverHelloDone
        case .waitingFinished: return .finished
        default: return .serverHello
        }
    }

    private func handleHelloVerifyRequest(
        _ body: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        let hvr = try HelloVerifyRequest.decode(from: body)
        s.context.cookie = hvr.cookie

        // Reset message seq and transcript for the retry
        s.context.messageSeq = 0
        s.context.handshakeMessages = Data()

        // Resend ClientHello with cookie. The original client random is reused, so
        // this construction does not invoke the CSPRNG.
        let clientHello = try DTLSClientHello(
            random: s.context.clientRandom,
            cookie: hvr.cookie,
            cipherSuites: supportedCipherSuites
        )

        let chBody = clientHello.encode()
        let msg = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: s.context.nextMessageSeq(),
            body: chBody
        )
        s.context.handshakeMessages.append(msg)

        s.state = .waitingServerHelloWithCookie
        return [.sendMessage(msg)]
    }

    private func handleServerHello(
        _ body: Data,
        state s: inout HandlerState
    ) throws {
        let serverHello = try DTLSServerHello.decode(from: body)
        s.context.serverRandom = serverHello.random
        s.context.cipherSuite = serverHello.cipherSuite
        s.context.keySchedule = DTLSKeySchedule(cipherSuite: serverHello.cipherSuite)
    }

    private func handleCertificate(
        _ body: Data,
        state s: inout HandlerState
    ) throws {
        let certMsg = try CertificateMessage.decode(from: body)
        guard let firstCert = certMsg.certificates.first else {
            throw DTLSError.invalidCertificate("Empty certificate chain")
        }
        s.context.serverCertificateDER = firstCert
    }

    private func handleServerKeyExchange(
        _ body: Data,
        state s: inout HandlerState
    ) throws {
        let ske = try ServerKeyExchange.decode(from: body)
        s.context.serverPublicKey = ske.publicKey
        s.context.serverNamedGroup = ske.namedGroup

        // Verify server signature using server's certificate
        if let certDER = s.context.serverCertificateDER {
            let verifyKey = try VerificationKey(certificateData: certDER)

            guard let clientRandom = s.context.clientRandom,
                  let serverRandom = s.context.serverRandom else {
                throw DTLSError.invalidState("Missing randoms")
            }

            let valid = try ske.verify(
                clientRandom: clientRandom,
                serverRandom: serverRandom,
                verificationKey: verifyKey
            )
            guard valid else {
                throw DTLSError.signatureVerificationFailed
            }
        }
    }

    private func handleServerHelloDone(
        _ body: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        _ = try ServerHelloDone.decode(from: body)

        guard let serverPublicKey = s.context.serverPublicKey,
              let serverNamedGroup = s.context.serverNamedGroup,
              let clientRandom = s.context.clientRandom,
              let serverRandom = s.context.serverRandom else {
            throw DTLSError.invalidState("Missing handshake data")
        }

        // Generate ECDHE key pair
        let keyExchange = try KeyExchange.generate(for: serverNamedGroup)
        s.context.keyExchange = keyExchange

        // Compute shared secret and derive master secret
        let sharedSecret = try keyExchange.sharedSecret(with: serverPublicKey)
        s.context.keySchedule?.deriveMasterSecret(
            preMasterSecret: sharedSecret.rawRepresentation,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        // Derive key block early for .keysAvailable
        guard let keyBlock = try s.context.keySchedule?.deriveKeyBlock() else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }
        guard let cipherSuite = s.context.cipherSuite else {
            throw DTLSError.invalidState("Cipher suite not negotiated")
        }

        var actions: [DTLSHandshakeAction] = []

        // Certificate message
        let certMsg = CertificateMessage(certificate: certificate)
        let certBody = certMsg.encode()
        let certEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .certificate,
            messageSeq: s.context.nextMessageSeq(),
            body: certBody
        )
        s.context.handshakeMessages.append(certEncoded)
        actions.append(.sendMessage(certEncoded))

        // ClientKeyExchange
        let cke = ClientKeyExchange(publicKey: keyExchange.publicKeyBytes)
        let ckeBody = cke.encode()
        let ckeEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .clientKeyExchange,
            messageSeq: s.context.nextMessageSeq(),
            body: ckeBody
        )
        s.context.handshakeMessages.append(ckeEncoded)
        actions.append(.sendMessage(ckeEncoded))

        // CertificateVerify
        let cvHash = Self.computeHandshakeHash(
            messages: s.context.handshakeMessages,
            cipherSuite: s.context.cipherSuite
        )
        let cv = try CertificateVerify.create(
            handshakeHash: cvHash,
            signingKey: certificate.signingKey
        )
        let cvBody = cv.encode()
        let cvEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .certificateVerify,
            messageSeq: s.context.nextMessageSeq(),
            body: cvBody
        )
        s.context.handshakeMessages.append(cvEncoded)
        actions.append(.sendMessage(cvEncoded))

        // Key material available (DTLSConnection stores but does not install yet)
        actions.append(.keysAvailable(keyBlock, cipherSuite))

        // ChangeCipherSpec (DTLSConnection installs write keys here)
        actions.append(.sendChangeCipherSpec)

        // Finished (will be encrypted since CCS was sent)
        let finishedHash = Self.computeHandshakeHash(
            messages: s.context.handshakeMessages,
            cipherSuite: s.context.cipherSuite
        )
        guard let verifyData = try s.context.keySchedule?.computeVerifyData(
            label: DTLSFinished.clientLabel,
            handshakeHash: finishedHash
        ) else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        let finished = DTLSFinished(verifyData: verifyData)
        let finBody = finished.encode()
        let finEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: s.context.nextMessageSeq(),
            body: finBody
        )
        s.context.handshakeMessages.append(finEncoded)
        actions.append(.sendMessage(finEncoded))

        // Expect CCS from server before server Finished
        actions.append(.expectChangeCipherSpec)

        s.state = .waitingChangeCipherSpec
        return actions
    }

    private func handleServerFinished(
        _ body: Data,
        rawMessage: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        let finished = try DTLSFinished.decode(from: body)

        // Verify server's Finished (hash computed BEFORE adding to transcript)
        let handshakeHash = Self.computeHandshakeHash(
            messages: s.context.handshakeMessages,
            cipherSuite: s.context.cipherSuite
        )
        guard let expectedVerifyData = try s.context.keySchedule?.computeVerifyData(
            label: DTLSFinished.serverLabel,
            handshakeHash: handshakeHash
        ) else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        guard constantTimeEqual(finished.verifyData, expectedVerifyData) else {
            throw DTLSError.verifyDataMismatch
        }

        // Record server Finished in transcript (after successful verification)
        s.context.handshakeMessages.append(rawMessage)

        s.state = .connected
        return [.handshakeComplete]
    }

    // MARK: - Helpers

    private static func computeHandshakeHash(
        messages: Data,
        cipherSuite: DTLSCipherSuite?
    ) -> Data {
        switch cipherSuite?.hashAlgorithm {
        case .sha384:
            return Data(SHA384.hash(data: messages))
        default:
            return Data(SHA256.hash(data: messages))
        }
    }

    /// Classification of a received handshake message_seq relative to the next
    /// expected one.
    fileprivate enum ReceiveSeqClass {
        /// Already-seen or stale message; discard silently (RFC 6347 retransmit).
        case duplicate
        /// Exactly the next expected message; process and advance.
        case inOrder
    }

    /// Classify a received message_seq, throwing on a future (gapped) seq.
    fileprivate static func classifyReceiveSeq(
        _ received: UInt16,
        expected: UInt16
    ) throws -> ReceiveSeqClass {
        if received == expected {
            return .inOrder
        }
        if received < expected {
            return .duplicate
        }
        // received > expected: a gap. We do not buffer; the peer will retransmit
        // in order. Surface it as a typed error rather than silently reprocessing.
        throw DTLSError.outOfOrderMessage(expected: expected, received: received)
    }
}

// MARK: - Server Handshake Handler

/// DTLS 1.2 handshake handler for the server side
public final class DTLSServerHandshakeHandler: Sendable {
    private let handlerState: Mutex<HandlerState>
    private let certificate: DTLSCertificate
    private let supportedCipherSuites: [DTLSCipherSuite]

    /// When `true`, the handshake fails unless the client presents a certificate
    /// AND proves possession of its private key via a valid CertificateVerify.
    ///
    /// Required for peer-authenticated deployments (WebRTC / libp2p) where the
    /// remote peer identity is bound to its certificate.
    private let requireClientCertificate: Bool

    /// Process-global rotating secret used to mint and verify HelloVerifyRequest
    /// cookies. Shared by default so the cookie check is stateless; injectable for
    /// tests.
    private let cookieProvider: DTLSCookieSecretProvider

    private struct HandlerState: Sendable {
        var state: DTLSServerState = .idle
        var context: DTLSServerContext = DTLSServerContext()
    }

    public init(
        certificate: DTLSCertificate,
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        requireClientCertificate: Bool = false,
        cookieProvider: DTLSCookieSecretProvider = .shared
    ) {
        self.certificate = certificate
        self.supportedCipherSuites = supportedCipherSuites
        self.requireClientCertificate = requireClientCertificate
        self.cookieProvider = cookieProvider
        self.handlerState = Mutex(HandlerState())
    }

    /// Process a ClientHello message
    ///
    /// Handles both the initial ClientHello (returns HelloVerifyRequest) and
    /// the retried ClientHello with cookie (returns server flight).
    ///
    /// - Parameters:
    ///   - rawMessage: Complete handshake message (12-byte DTLS header + body)
    ///   - clientAddress: Client's transport address for cookie computation
    /// - Returns: Actions for DTLSConnection to execute
    public func processClientHello(
        _ rawMessage: Data,
        clientAddress: Data
    ) throws -> [DTLSHandshakeAction] {
        try handlerState.withLock { s in
            // Parse ClientHello from raw message
            var reader = TLSReader(data: rawMessage)
            let header = try DTLSHandshakeHeader.decode(reader: &reader)
            let body = Data(try reader.readBytes(Int(header.fragmentLength)))
            let clientHello = try DTLSClientHello.decode(from: body)

            guard header.messageType == .clientHello else {
                throw DTLSError.unexpectedMessage(expected: .clientHello, received: header.messageType)
            }

            // If no cookie, send HelloVerifyRequest. The cookie is minted from a
            // process-global rotating secret bound to this ClientHello, so no
            // per-connection state is allocated for an unauthenticated peer.
            if clientHello.cookie.isEmpty {
                let hvr = HelloVerifyRequest.generate(
                    clientAddress: clientAddress,
                    clientHello: clientHello,
                    provider: cookieProvider
                )
                let hvrBody = hvr.encode()
                let msg = DTLSHandshakeHeader.encodeMessage(
                    type: .helloVerifyRequest,
                    messageSeq: s.context.nextMessageSeq(),
                    body: hvrBody
                )

                s.state = .waitingClientHelloWithCookie
                return [.sendMessage(msg)]
            }

            // A non-empty cookie was presented: it MUST validate. Because the secret
            // is process-global, there is always a secret to verify against — a
            // presented-but-unverifiable cookie is always rejected (never silently
            // accepted). The cookie is bound to this ClientHello's address, random,
            // and cipher suites, so a swapped ClientHello fails.
            let valid = HelloVerifyRequest.verifyCookie(
                clientHello.cookie,
                clientAddress: clientAddress,
                clientHello: clientHello,
                provider: cookieProvider
            )
            guard valid else {
                throw DTLSError.cookieMismatch
            }

            return try processVerifiedClientHello(
                clientHello,
                rawMessage: rawMessage,
                state: &s
            )
        }
    }

    /// Process a received handshake message (not ClientHello)
    ///
    /// Takes the raw handshake message bytes (header + body) to correctly
    /// record in the transcript hash.
    ///
    /// - Parameter rawMessage: Complete handshake message (12-byte DTLS header + body)
    /// - Returns: Actions for DTLSConnection to execute
    public func processHandshakeMessage(_ rawMessage: Data) throws -> [DTLSHandshakeAction] {
        try handlerState.withLock { s in
            var reader = TLSReader(data: rawMessage)
            let header = try DTLSHandshakeHeader.decode(reader: &reader)
            let body = Data(try reader.readBytes(Int(header.fragmentLength)))

            // RFC 6347 §4.2.2: order/dedup on message_seq BEFORE touching the
            // transcript. A duplicate (seq < expected) is silently discarded; a
            // future seq (seq > expected) is rejected.
            switch try DTLSClientHandshakeHandler.classifyReceiveSeq(
                header.messageSeq,
                expected: s.context.nextReceiveSeq
            ) {
            case .duplicate:
                return []
            case .inOrder:
                s.context.nextReceiveSeq = header.messageSeq &+ 1
            }

            // Record in transcript, except messages whose signature/MAC covers
            // the transcript and therefore must exclude themselves:
            // - Finished (verify_data covers everything before it)
            // - CertificateVerify (signs everything before it; recorded only
            //   after successful verification, see verifyClientCertificateVerify)
            if header.messageType != .finished && header.messageType != .certificateVerify {
                s.context.handshakeMessages.append(rawMessage)
            }

            switch (s.state, header.messageType) {
            case (.waitingClientKeyExchange, .certificate):
                let certMsg = try CertificateMessage.decode(from: body)
                s.context.clientCertificateDER = certMsg.certificates.first
                return []

            case (.waitingClientKeyExchange, .clientKeyExchange):
                return try handleClientKeyExchange(body, state: &s)

            case (.waitingClientKeyExchange, .certificateVerify),
                 (.waitingChangeCipherSpec, .certificateVerify):
                try verifyClientCertificateVerify(body, rawMessage: rawMessage, state: &s)
                return []

            case (.waitingFinished, .finished):
                return try handleClientFinished(body, rawMessage: rawMessage, state: &s)

            default:
                throw DTLSError.unexpectedMessage(
                    expected: .clientKeyExchange,
                    received: header.messageType
                )
            }
        }
    }

    /// Process a ChangeCipherSpec record
    public func processChangeCipherSpec() throws {
        try handlerState.withLock { s in
            guard s.state == .waitingChangeCipherSpec else {
                throw DTLSError.invalidState("Unexpected ChangeCipherSpec in state: \(s.state)")
            }
            s.state = .waitingFinished
        }
    }

    // MARK: - Accessors

    /// Whether the handshake is complete
    public var isComplete: Bool {
        handlerState.withLock { $0.state == .connected }
    }

    /// The current handshake state
    public var currentState: DTLSServerState {
        handlerState.withLock { $0.state }
    }

    /// The client's DER-encoded certificate (if mutual auth)
    public var clientCertificateDER: Data? {
        handlerState.withLock { $0.context.clientCertificateDER }
    }

    /// The negotiated cipher suite
    public var negotiatedCipherSuite: DTLSCipherSuite? {
        handlerState.withLock { $0.context.cipherSuite }
    }

    /// The next handshake message_seq this handler expects to receive from the
    /// peer (used for in-order processing and duplicate rejection).
    public var nextExpectedReceiveSeq: UInt16 {
        handlerState.withLock { $0.context.nextReceiveSeq }
    }

    // MARK: - Private Handlers

    private func processVerifiedClientHello(
        _ clientHello: DTLSClientHello,
        rawMessage: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        s.context.clientRandom = clientHello.random

        // Select cipher suite
        guard let selectedSuite = selectCipherSuite(from: clientHello.cipherSuites) else {
            throw DTLSError.noCipherSuiteMatch
        }
        s.context.cipherSuite = selectedSuite
        s.context.keySchedule = DTLSKeySchedule(cipherSuite: selectedSuite)

        // Reset transcript and record ClientHello (using actual raw bytes from peer)
        s.context.handshakeMessages = Data()
        s.context.handshakeMessages.append(rawMessage)

        // The cookie-carrying ClientHello is the client's message_seq 0 (the client
        // resets its send seq after the HelloVerifyRequest). The next handshake
        // message we expect to receive is the client's Certificate at seq 1.
        s.context.nextReceiveSeq = 1

        var actions: [DTLSHandshakeAction] = []

        // ServerHello
        let serverHello = try DTLSServerHello(cipherSuite: selectedSuite)
        s.context.serverRandom = serverHello.random
        let shBody = serverHello.encode()
        let shEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .serverHello,
            messageSeq: s.context.nextMessageSeq(),
            body: shBody
        )
        s.context.handshakeMessages.append(shEncoded)
        actions.append(.sendMessage(shEncoded))

        // Certificate
        let certMsg = CertificateMessage(certificate: certificate)
        let certBody = certMsg.encode()
        let certEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .certificate,
            messageSeq: s.context.nextMessageSeq(),
            body: certBody
        )
        s.context.handshakeMessages.append(certEncoded)
        actions.append(.sendMessage(certEncoded))

        // ServerKeyExchange
        let namedGroup: TLSCore.NamedGroup = .secp256r1
        let keyExchange = try KeyExchange.generate(for: namedGroup)
        s.context.keyExchange = keyExchange

        guard let clientRandom = s.context.clientRandom,
              let serverRandom = s.context.serverRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }

        let ske = try ServerKeyExchange.create(
            keyExchange: keyExchange,
            signingKey: certificate.signingKey,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )
        let skeBody = ske.encode()
        let skeEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .serverKeyExchange,
            messageSeq: s.context.nextMessageSeq(),
            body: skeBody
        )
        s.context.handshakeMessages.append(skeEncoded)
        actions.append(.sendMessage(skeEncoded))

        // ServerHelloDone
        let shd = ServerHelloDone()
        let shdBody = shd.encode()
        let shdEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .serverHelloDone,
            messageSeq: s.context.nextMessageSeq(),
            body: shdBody
        )
        s.context.handshakeMessages.append(shdEncoded)
        actions.append(.sendMessage(shdEncoded))

        s.state = .waitingClientKeyExchange
        return actions
    }

    private func handleClientKeyExchange(
        _ body: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        let cke = try ClientKeyExchange.decode(from: body)
        s.context.clientPublicKey = cke.publicKey

        // Compute shared secret
        guard let keyExchange = s.context.keyExchange else {
            throw DTLSError.invalidState("No key exchange")
        }
        let sharedSecret = try keyExchange.sharedSecret(with: cke.publicKey)

        guard let clientRandom = s.context.clientRandom,
              let serverRandom = s.context.serverRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }

        // Derive master secret
        s.context.keySchedule?.deriveMasterSecret(
            preMasterSecret: sharedSecret.rawRepresentation,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        // Derive key block early
        guard let keyBlock = try s.context.keySchedule?.deriveKeyBlock() else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }
        guard let cipherSuite = s.context.cipherSuite else {
            throw DTLSError.invalidState("Cipher suite not negotiated")
        }

        s.state = .waitingChangeCipherSpec

        return [
            .keysAvailable(keyBlock, cipherSuite),
            .expectChangeCipherSpec
        ]
    }

    /// Verify the client's CertificateVerify — its proof of possession of the
    /// private key for the certificate it presented (RFC 5246 §7.4.8).
    ///
    /// The signature covers the transcript hash over all handshake messages up
    /// to but EXCLUDING this CertificateVerify. The CertificateVerify is recorded
    /// in the transcript only after successful verification so the subsequent
    /// Finished hash includes it.
    private func verifyClientCertificateVerify(
        _ body: Data,
        rawMessage: Data,
        state s: inout HandlerState
    ) throws {
        guard let certDER = s.context.clientCertificateDER else {
            // CertificateVerify without a preceding Certificate is a protocol
            // violation — there is no key to verify possession against.
            throw DTLSError.unexpectedMessage(
                expected: .certificate,
                received: .certificateVerify
            )
        }

        let cv = try CertificateVerify.decode(from: body)
        let handshakeHash = Self.computeHandshakeHash(
            messages: s.context.handshakeMessages,
            cipherSuite: s.context.cipherSuite
        )
        let verificationKey = try VerificationKey(certificateData: certDER)
        let valid = try cv.verify(
            handshakeHash: handshakeHash,
            verificationKey: verificationKey
        )
        guard valid else {
            throw DTLSError.signatureVerificationFailed
        }

        s.context.clientCertificateVerified = true
        // Record CertificateVerify in the transcript now (after verification) so
        // the Finished hash covers it.
        s.context.handshakeMessages.append(rawMessage)
    }

    private func handleClientFinished(
        _ body: Data,
        rawMessage: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        let finished = try DTLSFinished.decode(from: body)

        // Enforce the client-authentication policy before completing the
        // handshake. A presented certificate MUST have been proven via
        // CertificateVerify; never complete with an unverified client identity.
        if requireClientCertificate {
            guard s.context.clientCertificateDER != nil,
                  s.context.clientCertificateVerified else {
                throw DTLSError.clientCertificateRequired
            }
        } else if s.context.clientCertificateDER != nil {
            guard s.context.clientCertificateVerified else {
                throw DTLSError.signatureVerificationFailed
            }
        }

        // Verify client's Finished (hash computed BEFORE adding to transcript)
        let handshakeHash = Self.computeHandshakeHash(
            messages: s.context.handshakeMessages,
            cipherSuite: s.context.cipherSuite
        )
        guard let expectedVerifyData = try s.context.keySchedule?.computeVerifyData(
            label: DTLSFinished.clientLabel,
            handshakeHash: handshakeHash
        ) else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        guard constantTimeEqual(finished.verifyData, expectedVerifyData) else {
            throw DTLSError.verifyDataMismatch
        }

        // Record client Finished in transcript (after successful verification)
        s.context.handshakeMessages.append(rawMessage)

        var actions: [DTLSHandshakeAction] = []

        // Server ChangeCipherSpec (DTLSConnection installs write keys)
        actions.append(.sendChangeCipherSpec)

        // Server Finished (will be encrypted since CCS was sent)
        let serverHash = Self.computeHandshakeHash(
            messages: s.context.handshakeMessages,
            cipherSuite: s.context.cipherSuite
        )
        guard let verifyData = try s.context.keySchedule?.computeVerifyData(
            label: DTLSFinished.serverLabel,
            handshakeHash: serverHash
        ) else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        let serverFinished = DTLSFinished(verifyData: verifyData)
        let sfBody = serverFinished.encode()
        let sfEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: s.context.nextMessageSeq(),
            body: sfBody
        )
        actions.append(.sendMessage(sfEncoded))

        actions.append(.handshakeComplete)

        s.state = .connected
        return actions
    }

    // MARK: - Helpers

    private func selectCipherSuite(from offered: [DTLSCipherSuite]) -> DTLSCipherSuite? {
        for suite in supportedCipherSuites {
            if offered.contains(suite) {
                return suite
            }
        }
        return nil
    }

    private static func computeHandshakeHash(
        messages: Data,
        cipherSuite: DTLSCipherSuite?
    ) -> Data {
        switch cipherSuite?.hashAlgorithm {
        case .sha384:
            return Data(SHA384.hash(data: messages))
        default:
            return Data(SHA256.hash(data: messages))
        }
    }
}
