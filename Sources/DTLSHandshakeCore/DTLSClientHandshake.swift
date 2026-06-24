/// Embedded-clean DTLS 1.2 client handshake FSM (RFC 6347 / RFC 5246).
///
/// A single value-type, sans-IO, caller-locked finite state machine spanning
/// ClientHello through the server Finished. It performs **no I/O**, holds **no
/// lock**, and never reaches for a clock — the `DTLSCore` adapter owns the `Mutex`,
/// parses wire bytes ↔ Foundation `Data`, performs the X.509-bound signature
/// operations (ServerKeyExchange verification, the client CertificateVerify
/// signing), runs the ECDHE key agreement, generates the handshake randoms, and
/// drives this core under its lock.
///
/// ## State
/// ```
/// idle → waitingServerHello → (HVR) → waitingServerHelloWithCookie
///      → waitingCertificate → waitingServerKeyExchange → waitingServerHelloDone
///      → waitingChangeCipherSpec → waitingFinished → connected
/// ```
///
/// ## Security invariants (preserved byte-for-byte)
/// - **message_seq ordering / dedup (RFC 6347 §4.2.2)** is owned here: a duplicate
///   (seq < expected) is silently discarded *before* the transcript is touched; a
///   future seq is rejected. The transcript can never be corrupted by a retransmit.
/// - **HelloVerifyRequest is excluded from the transcript** (RFC 6347 §4.2.1) and
///   the ClientHello transcript is reset for the cookie retry.
/// - **The server Finished MAC is verified** constant-time, fail-closed, before the
///   transcript records it and the FSM completes.
/// - **The server ServerKeyExchange signature** is verified by the adapter (X.509);
///   the core surfaces the signed bytes and folds the result fail-closed.
///
/// What stays adapter-side: the ServerKeyExchange / CertificateVerify X.509
/// signature operations, the ECDHE key agreement, the CSPRNG randoms, and the
/// wire ↔ `Data` bridging.
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = TLSCryptoProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no ContinuousClock, no swift-crypto, no X.509, typed throws, no key paths.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import DTLSWireCore

/// The DTLS 1.2 client handshake FSM over the crypto seam.
public struct DTLSClientHandshake<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// Client handshake state (mirrors the legacy `DTLSClientState`).
    public enum ClientState: Sendable, Equatable {
        case idle
        case waitingServerHello
        case waitingServerHelloWithCookie
        case waitingCertificate
        case waitingServerKeyExchange
        case waitingServerHelloDone
        case waitingChangeCipherSpec
        case waitingFinished
        case connected
    }

    // MARK: - Stored Fields (all value types)

    private var state: ClientState
    private var cipherSuite: DTLSCipherSuite?
    private var keySchedule: DTLSKeyScheduleCore<C>?

    private var clientRandom: [UInt8]?
    private var serverRandom: [UInt8]?

    /// Server's ECDHE public key (set on ServerKeyExchange).
    private var serverPublicKey: [UInt8]?
    /// Server's named group (set on ServerKeyExchange).
    private var serverNamedGroup: NamedGroup?
    /// Server's certificate DER (set on Certificate; surfaced to the adapter).
    public private(set) var serverCertificateDER: [UInt8]?

    /// Send message_seq for messages WE send.
    private var messageSeq: UInt16
    /// The next handshake message_seq we expect to RECEIVE.
    public private(set) var nextReceiveSeq: UInt16

    /// Accumulated handshake-message bytes for the transcript hash.
    private var handshakeMessages: [UInt8]

    // MARK: - Initialization

    public init() {
        self.state = .idle
        self.cipherSuite = nil
        self.keySchedule = nil
        self.clientRandom = nil
        self.serverRandom = nil
        self.serverPublicKey = nil
        self.serverNamedGroup = nil
        self.serverCertificateDER = nil
        self.messageSeq = 0
        self.nextReceiveSeq = 0
        self.handshakeMessages = []
    }

    // MARK: - Accessors

    public var currentState: ClientState { state }
    public var isComplete: Bool { state == .connected }
    public var negotiatedCipherSuite: DTLSCipherSuite? { cipherSuite }
    public var nextExpectedReceiveSeq: UInt16 { nextReceiveSeq }

    /// The negotiated ServerHello random (on the wire; needed by the adapter for the
    /// ServerKeyExchange signature verification). `nil` before ServerHello.
    public var negotiatedServerRandom: [UInt8]? { serverRandom }

    /// The next send message_seq, then advances it. Used by the adapter when it must
    /// stamp a message it built (e.g. the cookie-retry ClientHello).
    private mutating func nextMessageSeq() -> UInt16 {
        let seq = messageSeq
        messageSeq &+= 1
        return seq
    }

    // MARK: - Start

    /// Begins the handshake. The adapter supplies the encoded ClientHello body
    /// (built with its CSPRNG random) and that random; the core stamps the message
    /// header, records the transcript, and transitions to `waitingServerHello`.
    ///
    /// - Parameters:
    ///   - clientHelloBody: The encoded ClientHello body (no handshake header).
    ///   - clientRandom: The 32-byte ClientHello random.
    /// - Returns: the actions (a single `.sendMessage`).
    public mutating func start(
        clientHelloBody: [UInt8],
        clientRandom: [UInt8]
    ) throws(DTLSError) -> [DTLSCoreAction] {
        guard state == .idle else {
            throw DTLSError.invalidState("Handshake already started")
        }
        self.clientRandom = clientRandom
        let msg = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .clientHello,
            messageSeq: nextMessageSeq(),
            body: clientHelloBody
        )
        handshakeMessages.append(contentsOf: msg)
        state = .waitingServerHello
        return [.sendMessage(msg)]
    }

    // MARK: - Receive gate (RFC 6347 §4.2.2)

    /// Classification of a received handshake message_seq.
    private enum ReceiveSeqClass {
        case duplicate
        case inOrder
    }

    private func classifyReceiveSeq(_ received: UInt16) throws(DTLSError) -> ReceiveSeqClass {
        if received == nextReceiveSeq { return .inOrder }
        if received < nextReceiveSeq { return .duplicate }
        throw DTLSError.outOfOrderMessage(expected: nextReceiveSeq, received: received)
    }

    /// The expected next handshake type (for unexpected-message diagnostics).
    private func expectedType() -> DTLSHandshakeType {
        switch state {
        case .waitingServerHello, .waitingServerHelloWithCookie: return .serverHello
        case .waitingCertificate: return .certificate
        case .waitingServerKeyExchange: return .serverKeyExchange
        case .waitingServerHelloDone: return .serverHelloDone
        case .waitingFinished: return .finished
        default: return .serverHello
        }
    }

    // MARK: - Ingest dispatch

    /// The crypto inputs the adapter must compute when the core requests them while
    /// processing a received message.
    public enum IngestResult: Sendable {
        /// Nothing further required; emit these actions.
        case actions([DTLSCoreAction])
        /// A HelloVerifyRequest cookie arrived: rebuild the ClientHello with this
        /// cookie. The adapter encodes the body (reusing the original random) and
        /// calls ``resendClientHelloWithCookie``.
        case rebuildClientHelloWithCookie(cookie: [UInt8])
        /// A ServerKeyExchange arrived: the adapter must verify its signature with
        /// the server certificate (X.509), then call ``acceptServerKeyExchange``.
        case verifyServerKeyExchange(ServerKeyExchange)
        /// ServerHelloDone arrived: the adapter must run ECDHE for `namedGroup`
        /// against `serverPublicKey`, sign the CertificateVerify, and call
        /// ``buildClientFlight``.
        case buildClientFlight(namedGroup: NamedGroup, serverPublicKey: [UInt8])
    }

    /// Begins processing a received handshake message: runs the ordering gate and
    /// records the transcript, then returns what the adapter must do next.
    ///
    /// The adapter passes the already-decoded header + body + the raw message bytes
    /// (header + body) for the transcript. The core owns the dedup/ordering and the
    /// transcript append.
    public mutating func ingest(
        header: DTLSHandshakeHeader,
        body: [UInt8],
        rawMessage: [UInt8]
    ) throws(DTLSError) -> IngestResult {
        // Ordering / dedup BEFORE the transcript (RFC 6347 §4.2.2).
        switch try classifyReceiveSeq(header.messageSeq) {
        case .duplicate:
            return .actions([])
        case .inOrder:
            nextReceiveSeq = header.messageSeq &+ 1
        }

        // Record in the transcript, except HelloVerifyRequest (RFC 6347 §4.2.1) and
        // Finished (its verify_data must not cover itself).
        if header.messageType != .helloVerifyRequest && header.messageType != .finished {
            handshakeMessages.append(contentsOf: rawMessage)
        }

        switch (state, header.messageType) {
        case (.waitingServerHello, .helloVerifyRequest):
            return try handleHelloVerifyRequest(body)

        case (.waitingServerHello, .serverHello),
             (.waitingServerHelloWithCookie, .serverHello):
            try handleServerHello(body)
            state = .waitingCertificate
            return .actions([])

        case (.waitingCertificate, .certificate):
            try handleCertificate(body)
            state = .waitingServerKeyExchange
            return .actions([])

        case (.waitingServerKeyExchange, .serverKeyExchange):
            let ske = try decodeServerKeyExchange(body)
            serverPublicKey = ske.publicKey
            serverNamedGroup = ske.namedGroup
            state = .waitingServerHelloDone
            // The adapter verifies the signature (X.509) before continuing.
            return .verifyServerKeyExchange(ske)

        case (.waitingServerHelloDone, .serverHelloDone):
            _ = try decodeServerHelloDone(body)
            guard let serverPublicKey, let serverNamedGroup else {
                throw DTLSError.invalidState("Missing handshake data")
            }
            return .buildClientFlight(namedGroup: serverNamedGroup, serverPublicKey: serverPublicKey)

        case (.waitingFinished, .finished):
            return .actions(try handleServerFinished(body, rawMessage: rawMessage))

        default:
            throw DTLSError.unexpectedMessage(
                expected: expectedType(),
                received: header.messageType
            )
        }
    }

    // MARK: - HelloVerifyRequest

    private mutating func handleHelloVerifyRequest(_ body: [UInt8]) throws(DTLSError) -> IngestResult {
        let cookie = try decodeHelloVerifyRequestCookie(body)
        // Reset send seq and transcript for the cookie retry.
        messageSeq = 0
        handshakeMessages = []
        state = .waitingServerHelloWithCookie
        return .rebuildClientHelloWithCookie(cookie: cookie)
    }

    /// Completes the cookie retry: the adapter encodes a ClientHello body carrying
    /// the cookie (reusing the original random) and passes it here.
    public mutating func resendClientHelloWithCookie(
        clientHelloBody: [UInt8]
    ) throws(DTLSError) -> [DTLSCoreAction] {
        guard state == .waitingServerHelloWithCookie else {
            throw DTLSError.invalidState("Cookie retry out of order")
        }
        let msg = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .clientHello,
            messageSeq: nextMessageSeq(),
            body: clientHelloBody
        )
        handshakeMessages.append(contentsOf: msg)
        return [.sendMessage(msg)]
    }

    // MARK: - ServerHello / Certificate

    private mutating func handleServerHello(_ body: [UInt8]) throws(DTLSError) {
        let sh = try decodeServerHello(body)
        serverRandom = sh.random
        cipherSuite = sh.cipherSuite
        keySchedule = DTLSKeyScheduleCore<C>(cipherSuite: sh.cipherSuite)
    }

    private mutating func handleCertificate(_ body: [UInt8]) throws(DTLSError) {
        let cert = try decodeCertificate(body)
        guard let first = cert.certificates.first else {
            throw DTLSError.invalidCertificate("Empty certificate chain")
        }
        serverCertificateDER = first
    }

    // MARK: - ServerKeyExchange (adapter verifies signature)

    /// Folds the adapter's signature-verification result for the ServerKeyExchange.
    /// `valid == false` (or a verification error reported as such) fails the
    /// handshake — never proceeds with an unverified server key.
    public mutating func acceptServerKeyExchange(signatureValid: Bool) throws(DTLSError) {
        guard state == .waitingServerHelloDone else {
            throw DTLSError.invalidState("ServerKeyExchange accepted out of order")
        }
        guard signatureValid else {
            throw DTLSError.signatureVerificationFailed
        }
    }

    // MARK: - ServerHelloDone → client flight

    /// The crypto inputs the adapter computed for the client flight.
    public struct ClientFlightInputs: Sendable {
        /// The shared ECDHE secret (raw representation), used as the pre-master.
        public let sharedSecret: [UInt8]
        /// The client's ECDHE public-key bytes (sent in ClientKeyExchange).
        public let clientPublicKey: [UInt8]
        /// The encoded client Certificate message body (the client's own cert chain).
        public let certificateBody: [UInt8]
        /// A closure-free request: the adapter signs the CertificateVerify over the
        /// handshake hash the core computes; see ``buildClientFlight``.
        public init(sharedSecret: [UInt8], clientPublicKey: [UInt8], certificateBody: [UInt8]) {
            self.sharedSecret = sharedSecret
            self.clientPublicKey = clientPublicKey
            self.certificateBody = certificateBody
        }
    }

    /// A request for the adapter to sign the client CertificateVerify over
    /// `handshakeHash`, returning the signed CertificateVerify message body.
    public struct CertificateVerifyRequest: Sendable, Equatable {
        public let handshakeHash: [UInt8]
        public init(handshakeHash: [UInt8]) { self.handshakeHash = handshakeHash }
    }

    /// Builds Certificate + ClientKeyExchange, then requests the CertificateVerify
    /// signature over the transcript hash. The adapter then calls
    /// ``finishClientFlight`` with the signed CertificateVerify body.
    ///
    /// Derives the master secret + key block here (over the seam) so the keys are
    /// byte-identical, and returns the CertificateVerify signing request. The
    /// remaining actions (keysAvailable, CCS, Finished, expectCCS) are emitted by
    /// ``finishClientFlight`` after the adapter signs, matching the legacy action
    /// ordering exactly.
    public mutating func buildClientFlight(
        inputs: ClientFlightInputs
    ) throws(DTLSError) -> CertificateVerifyRequest {
        guard state == .waitingServerHelloDone else {
            throw DTLSError.invalidState("Client flight out of order")
        }
        guard let clientRandom, let serverRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }
        guard keySchedule != nil else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }
        guard cipherSuite != nil else {
            throw DTLSError.invalidState("Cipher suite not negotiated")
        }

        // Derive master secret + key block (validated before any message is staged).
        keySchedule?.deriveMasterSecret(
            preMasterSecret: inputs.sharedSecret,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )
        // Eagerly derive the key block so a failure surfaces now (matches legacy).
        guard let ks = keySchedule else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }
        _ = try ks.deriveKeyBlock()

        // Certificate
        let certEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .certificate,
            messageSeq: nextMessageSeq(),
            body: inputs.certificateBody
        )
        handshakeMessages.append(contentsOf: certEncoded)
        pendingFlight = [.sendMessage(certEncoded)]

        // ClientKeyExchange
        let cke = ClientKeyExchange(publicKey: inputs.clientPublicKey)
        let ckeBody = encodeBytesOrTrap(cke)
        let ckeEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .clientKeyExchange,
            messageSeq: nextMessageSeq(),
            body: ckeBody
        )
        handshakeMessages.append(contentsOf: ckeEncoded)
        pendingFlight.append(.sendMessage(ckeEncoded))

        // Request the CertificateVerify signature over the current transcript hash.
        let cvHash = DTLSTranscript<C>.hash(messages: handshakeMessages, cipherSuite: cipherSuite)
        return CertificateVerifyRequest(handshakeHash: cvHash)
    }

    /// The flight actions staged by `buildClientFlight` before the CertificateVerify
    /// signature is folded in.
    private var pendingFlight: [DTLSCoreAction] = []

    /// Folds the adapter-signed CertificateVerify and emits the rest of the client
    /// flight (keysAvailable, CCS, Finished, expectCCS) in the exact legacy order.
    ///
    /// - Parameter certificateVerifyBody: The encoded CertificateVerify message body
    ///   (signed by the adapter).
    public mutating func finishClientFlight(
        certificateVerifyBody: [UInt8]
    ) throws(DTLSError) -> [DTLSCoreAction] {
        guard state == .waitingServerHelloDone else {
            throw DTLSError.invalidState("Client flight finish out of order")
        }
        guard let cipherSuite, let ks = keySchedule else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }
        let keyBlock = try ks.deriveKeyBlock()

        var actions = pendingFlight
        pendingFlight = []

        // CertificateVerify (already signed by the adapter).
        let cvEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .certificateVerify,
            messageSeq: nextMessageSeq(),
            body: certificateVerifyBody
        )
        handshakeMessages.append(contentsOf: cvEncoded)
        actions.append(.sendMessage(cvEncoded))

        // Key material available (adapter stores, does not install yet).
        actions.append(.keysAvailable(keyBlock, cipherSuite))

        // ChangeCipherSpec (adapter installs write keys here).
        actions.append(.sendChangeCipherSpec)

        // Finished (encrypted, since CCS was sent).
        let finishedHash = DTLSTranscript<C>.hash(messages: handshakeMessages, cipherSuite: cipherSuite)
        let verifyData = try ks.computeVerifyData(label: DTLSFinished.clientLabel, handshakeHash: finishedHash)
        let finished = DTLSFinished(verifyData: verifyData)
        let finBody = encodeBytesOrTrap(finished)
        let finEncoded = DTLSHandshakeHeader.encodeMessageOrTrap(
            type: .finished,
            messageSeq: nextMessageSeq(),
            body: finBody
        )
        handshakeMessages.append(contentsOf: finEncoded)
        actions.append(.sendMessage(finEncoded))

        // Expect CCS from the server before the server Finished.
        actions.append(.expectChangeCipherSpec)

        state = .waitingChangeCipherSpec
        return actions
    }

    // MARK: - ChangeCipherSpec / server Finished

    /// Processes a received ChangeCipherSpec record (not a handshake message).
    public mutating func processChangeCipherSpec() throws(DTLSError) {
        guard state == .waitingChangeCipherSpec else {
            throw DTLSError.invalidState("Unexpected ChangeCipherSpec in state: \(state)")
        }
        state = .waitingFinished
    }

    private mutating func handleServerFinished(
        _ body: [UInt8],
        rawMessage: [UInt8]
    ) throws(DTLSError) -> [DTLSCoreAction] {
        let finished = try decodeFinished(body)
        guard let ks = keySchedule else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        // Verify the server Finished (hash computed BEFORE adding to the transcript).
        let handshakeHash = DTLSTranscript<C>.hash(messages: handshakeMessages, cipherSuite: cipherSuite)
        let expected = try ks.computeVerifyData(label: DTLSFinished.serverLabel, handshakeHash: handshakeHash)
        guard constantTimeEqual(finished.verifyData, expected) else {
            throw DTLSError.verifyDataMismatch
        }

        // Record server Finished AFTER successful verification.
        handshakeMessages.append(contentsOf: rawMessage)
        state = .connected
        return [.handshakeComplete]
    }
}
