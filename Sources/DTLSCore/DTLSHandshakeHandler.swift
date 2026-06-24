/// DTLS 1.2 Handshake Handler — Foundation adapter over the Embedded-clean FSM.
///
/// These handlers keep the historical `Data`-based, `Mutex`-protected public API and
/// drive the Embedded-clean `DTLSHandshakeCore` FSM (`DTLSClientHandshake<C>` /
/// `DTLSServerHandshake<C>`, specialised at `C = TLSCryptoProvider`). The FSM
/// owns the state machine, message_seq ordering/dedup, transcript accumulation, the
/// DTLS 1.2 PRF + key schedule (over the crypto seam), and the Finished MAC; this
/// adapter owns everything that cannot live in an Embedded target:
///
/// - the X.509-bound signature operations (ServerKeyExchange sign/verify, the
///   CertificateVerify sign/verify) via `SigningKey` / `VerificationKey`,
/// - the ECDHE key agreement (`KeyExchange`),
/// - the CSPRNG randoms (ClientHello / ServerHello),
/// - the HelloVerifyRequest cookie minting / verification (the rotating
///   `DTLSCookieSecretProvider` HMAC),
/// - the `Mutex`, and the `Data` ↔ `[UInt8]` bridging.
///
/// All security invariants are preserved byte-for-byte: the cookie binding check is
/// fail-closed, the client CertificateVerify proof-of-possession is verified
/// whenever a certificate is presented (independent of `requireClientCertificate`),
/// replay/ordering protection is owned by the FSM, and the Finished MAC is verified
/// constant-time. The wire flight, transcripts, and secrets are identical to the
/// pre-FSM implementation.
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
import DTLSHandshakeCore

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

// MARK: - Action bridging

/// Translates the Embedded-clean ``DTLSCoreAction`` stream into the Foundation
/// ``DTLSHandshakeAction`` stream, bridging `[UInt8]` ↔ `Data` and the core key
/// block ↔ `DTLSKeyBlock`. Order is preserved verbatim.
private func bridge(_ actions: [DTLSCoreAction]) -> [DTLSHandshakeAction] {
    actions.map { action in
        switch action {
        case .sendMessage(let bytes):
            return .sendMessage(Data(bytes))
        case .sendChangeCipherSpec:
            return .sendChangeCipherSpec
        case .keysAvailable(let kb, let suite):
            return .keysAvailable(DTLSKeyBlock(core: kb), suite)
        case .expectChangeCipherSpec:
            return .expectChangeCipherSpec
        case .handshakeComplete:
            return .handshakeComplete
        }
    }
}

// MARK: - Client Handshake Handler

/// DTLS 1.2 handshake handler for the client side
public final class DTLSClientHandshakeHandler: Sendable {
    private let handlerState: Mutex<HandlerState>
    private let certificate: DTLSCertificate
    private let supportedCipherSuites: [DTLSCipherSuite]

    private struct HandlerState: Sendable {
        var fsm = DTLSClientHandshake<TLSCryptoProvider>()
        /// Our ECDHE key pair (created on ServerHelloDone).
        var keyExchange: KeyExchange?
        /// The original ClientHello random, reused for the cookie retry.
        var clientRandom: Data?
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
            let clientHello = try DTLSClientHello(cipherSuites: supportedCipherSuites)
            s.clientRandom = Data(clientHello.random)
            let body = clientHello.encode()
            let actions = try toDTLSError {
                try s.fsm.start(
                    clientHelloBody: [UInt8](body),
                    clientRandom: clientHello.random
                )
            }
            return bridge(actions)
        }
    }

    /// Process a received handshake message
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

            let result = try toDTLSError {
                try s.fsm.ingest(
                    header: header,
                    body: [UInt8](body),
                    rawMessage: [UInt8](rawMessage)
                )
            }

            switch result {
            case .actions(let actions):
                return bridge(actions)

            case .rebuildClientHelloWithCookie(let cookie):
                // Rebuild the ClientHello reusing the original random + this cookie.
                guard let random = s.clientRandom else {
                    throw DTLSError.invalidState("Missing client random for cookie retry")
                }
                let clientHello = try DTLSClientHello(
                    random: random,
                    cookie: Data(cookie),
                    cipherSuites: supportedCipherSuites
                )
                let actions = try toDTLSError {
                    try s.fsm.resendClientHelloWithCookie(
                        clientHelloBody: [UInt8](clientHello.encode())
                    )
                }
                return bridge(actions)

            case .verifyServerKeyExchange(let ske):
                // Verify the server signature against the server's certificate (X.509).
                let valid = try verifyServerKeyExchange(ske, state: &s)
                try s.fsm.acceptServerKeyExchange(signatureValid: valid)
                return []

            case .buildClientFlight(let namedGroup, let serverPublicKey):
                return try buildClientFlight(
                    namedGroup: namedGroup,
                    serverPublicKey: Data(serverPublicKey),
                    state: &s
                )
            }
        }
    }

    /// Process a ChangeCipherSpec record (not a handshake message)
    public func processChangeCipherSpec() throws {
        try handlerState.withLock { s in
            try s.fsm.processChangeCipherSpec()
        }
    }

    // MARK: - Accessors

    /// Whether the handshake is complete
    public var isComplete: Bool {
        handlerState.withLock { $0.fsm.isComplete }
    }

    /// The current handshake state
    public var currentState: DTLSClientState {
        handlerState.withLock { DTLSClientState(core: $0.fsm.currentState) }
    }

    /// The server's DER-encoded certificate (available after Certificate message)
    public var serverCertificateDER: Data? {
        handlerState.withLock { $0.fsm.serverCertificateDER.map { Data($0) } }
    }

    /// The negotiated cipher suite (available after ServerHello)
    public var negotiatedCipherSuite: DTLSCipherSuite? {
        handlerState.withLock { $0.fsm.negotiatedCipherSuite }
    }

    /// The next handshake message_seq this handler expects to receive from the
    /// peer (used for in-order processing and duplicate rejection).
    public var nextExpectedReceiveSeq: UInt16 {
        handlerState.withLock { $0.fsm.nextExpectedReceiveSeq }
    }

    // MARK: - Private crypto (X.509 / ECDHE)

    private func verifyServerKeyExchange(
        _ ske: ServerKeyExchange,
        state s: inout HandlerState
    ) throws -> Bool {
        guard let certDER = s.fsm.serverCertificateDER else {
            // No certificate seen — preserve the legacy behaviour, which only
            // verified the SKE signature when a certificate was present.
            return true
        }
        let verifyKey = try VerificationKey(certificateData: Data(certDER))
        guard let clientRandom = s.clientRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }
        // The server random (on the wire) is folded into the SKE signed data. It is
        // surfaced by the FSM after ServerHello is processed.
        guard let serverRandom = s.fsm.negotiatedServerRandom else {
            throw DTLSError.invalidState("Missing server random")
        }
        return try ske.verify(
            clientRandom: clientRandom,
            serverRandom: Data(serverRandom),
            verificationKey: verifyKey
        )
    }

    private func buildClientFlight(
        namedGroup: NamedGroup,
        serverPublicKey: Data,
        state s: inout HandlerState
    ) throws -> [DTLSHandshakeAction] {
        // Generate the ECDHE key pair and compute the shared secret.
        let keyExchange = try KeyExchange.generate(for: namedGroup)
        s.keyExchange = keyExchange
        let sharedSecret = try keyExchange.sharedSecret(with: serverPublicKey)

        // The client's own Certificate message body.
        let certMsg = CertificateMessage(certificate: certificate)
        let certBody = certMsg.encode()

        let inputs = DTLSClientHandshake<TLSCryptoProvider>.ClientFlightInputs(
            sharedSecret: [UInt8](sharedSecret.rawRepresentation),
            clientPublicKey: [UInt8](keyExchange.publicKeyBytes),
            certificateBody: [UInt8](certBody)
        )

        // The core derives the keys + transcript and returns the CertificateVerify
        // signing request (the transcript hash to sign over).
        let cvRequest = try s.fsm.buildClientFlight(inputs: inputs)

        // Sign the CertificateVerify with our private key (X.509).
        let cv = try CertificateVerify.create(
            handshakeHash: Data(cvRequest.handshakeHash),
            signingKey: certificate.signingKey
        )
        let cvBody = cv.encode()

        let actions = try toDTLSError {
            try s.fsm.finishClientFlight(certificateVerifyBody: [UInt8](cvBody))
        }
        return bridge(actions)
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
    private let requireClientCertificate: Bool

    /// Process-global rotating secret used to mint and verify HelloVerifyRequest
    /// cookies.
    private let cookieProvider: DTLSCookieSecretProvider

    private struct HandlerState: Sendable {
        var fsm: DTLSServerHandshake<TLSCryptoProvider>
        /// Our ECDHE key pair (created when building the server flight).
        var keyExchange: KeyExchange?

        init(requireClientCertificate: Bool) {
            self.fsm = DTLSServerHandshake<TLSCryptoProvider>(
                requireClientCertificate: requireClientCertificate
            )
        }
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
        self.handlerState = Mutex(HandlerState(requireClientCertificate: requireClientCertificate))
    }

    /// Process a ClientHello message
    ///
    /// Handles both the initial ClientHello (returns HelloVerifyRequest) and
    /// the retried ClientHello with cookie (returns server flight).
    public func processClientHello(
        _ rawMessage: Data,
        clientAddress: Data
    ) throws -> [DTLSHandshakeAction] {
        try handlerState.withLock { s in
            var reader = TLSReader(data: rawMessage)
            let header = try DTLSHandshakeHeader.decode(reader: &reader)
            let body = Data(try reader.readBytes(Int(header.fragmentLength)))

            let outcome = try toDTLSError {
                try s.fsm.ingestClientHello(header: header, body: [UInt8](body))
            }

            switch outcome {
            case .needCookie(let clientHello):
                // Mint a cookie bound to this ClientHello and emit HelloVerifyRequest.
                let hvr = HelloVerifyRequest.generate(
                    clientAddress: clientAddress,
                    clientHello: clientHello,
                    provider: cookieProvider
                )
                let actions = try toDTLSError {
                    try s.fsm.emitHelloVerifyRequest(helloVerifyRequestBody: [UInt8](hvr.encode()))
                }
                return bridge(actions)

            case .verifyCookie(let clientHello):
                // Verify the presented cookie (HMAC, fail-closed): a presented-but-
                // unverifiable cookie is always rejected (never silently accepted).
                let valid = HelloVerifyRequest.verifyCookie(
                    Data(clientHello.cookie),
                    clientAddress: clientAddress,
                    clientHello: clientHello,
                    provider: cookieProvider
                )

                guard let selectedSuite = selectCipherSuite(from: clientHello.cipherSuites) else {
                    // Only after a valid cookie do we negotiate. If the cookie is
                    // invalid, the core rejects below before reaching negotiation —
                    // but a valid cookie with no suite match is a real negotiation
                    // failure.
                    if valid {
                        throw DTLSError.noCipherSuiteMatch
                    }
                    // Invalid cookie: let the core fail-close on the cookie check.
                    let inputs = try emptyFlightInputs()
                    _ = try toDTLSError {
                        try s.fsm.acceptCookieAndBuildFlight(
                            clientHello: clientHello,
                            rawMessage: [UInt8](rawMessage),
                            cookieValid: valid,
                            selectedSuite: .ecdheEcdsaWithAes128GcmSha256,
                            inputs: inputs
                        )
                    }
                    return []
                }

                // Build the signed server-flight inputs (only meaningful when the
                // cookie validates; the core rejects an invalid cookie first).
                let inputs = try buildServerFlightInputs(
                    clientHello: clientHello,
                    selectedSuite: selectedSuite,
                    state: &s,
                    cookieValid: valid
                )
                let actions = try toDTLSError {
                    try s.fsm.acceptCookieAndBuildFlight(
                        clientHello: clientHello,
                        rawMessage: [UInt8](rawMessage),
                        cookieValid: valid,
                        selectedSuite: selectedSuite,
                        inputs: inputs
                    )
                }
                return bridge(actions)
            }
        }
    }

    /// Process a received handshake message (not ClientHello)
    public func processHandshakeMessage(_ rawMessage: Data) throws -> [DTLSHandshakeAction] {
        try handlerState.withLock { s in
            var reader = TLSReader(data: rawMessage)
            let header = try DTLSHandshakeHeader.decode(reader: &reader)
            let body = Data(try reader.readBytes(Int(header.fragmentLength)))

            let result = try toDTLSError {
                try s.fsm.ingest(
                    header: header,
                    body: [UInt8](body),
                    rawMessage: [UInt8](rawMessage)
                )
            }

            switch result {
            case .actions(let actions):
                return bridge(actions)

            case .computeSharedSecret(let clientPublicKey):
                guard let keyExchange = s.keyExchange else {
                    throw DTLSError.invalidState("No key exchange")
                }
                let sharedSecret = try keyExchange.sharedSecret(with: Data(clientPublicKey))
                let actions = try toDTLSError {
                    try s.fsm.acceptClientKeyExchange(
                        sharedSecret: [UInt8](sharedSecret.rawRepresentation)
                    )
                }
                return bridge(actions)

            case .verifyCertificateVerify(let handshakeHash, let rawCV):
                let valid = try verifyClientCertificateVerify(
                    body: body,
                    handshakeHash: Data(handshakeHash),
                    state: &s
                )
                try toDTLSError {
                    try s.fsm.acceptClientCertificateVerify(
                        signatureValid: valid,
                        rawMessage: rawCV
                    )
                }
                return []
            }
        }
    }

    /// Process a ChangeCipherSpec record
    public func processChangeCipherSpec() throws {
        try handlerState.withLock { s in
            try s.fsm.processChangeCipherSpec()
        }
    }

    // MARK: - Accessors

    /// Whether the handshake is complete
    public var isComplete: Bool {
        handlerState.withLock { $0.fsm.isComplete }
    }

    /// The current handshake state
    public var currentState: DTLSServerState {
        handlerState.withLock { DTLSServerState(core: $0.fsm.currentState) }
    }

    /// The client's DER-encoded certificate (if mutual auth)
    public var clientCertificateDER: Data? {
        handlerState.withLock { $0.fsm.clientCertificateDER.map { Data($0) } }
    }

    /// The negotiated cipher suite
    public var negotiatedCipherSuite: DTLSCipherSuite? {
        handlerState.withLock { $0.fsm.negotiatedCipherSuite }
    }

    /// The next handshake message_seq this handler expects to receive from the
    /// peer (used for in-order processing and duplicate rejection).
    public var nextExpectedReceiveSeq: UInt16 {
        handlerState.withLock { $0.fsm.nextExpectedReceiveSeq }
    }

    // MARK: - Private crypto (X.509 / ECDHE)

    private func selectCipherSuite(from offered: [DTLSCipherSuite]) -> DTLSCipherSuite? {
        for suite in supportedCipherSuites where offered.contains(suite) {
            return suite
        }
        return nil
    }

    /// Builds the signed server-flight inputs: a fresh ServerHello random, the
    /// server's Certificate body, and the signed ServerKeyExchange body. Skipped
    /// (placeholder) when the cookie is invalid, since the core fails closed first.
    private func buildServerFlightInputs(
        clientHello: DTLSClientHello,
        selectedSuite: DTLSCipherSuite,
        state s: inout HandlerState,
        cookieValid: Bool
    ) throws -> DTLSServerHandshake<TLSCryptoProvider>.ServerFlightInputs {
        guard cookieValid else {
            return try emptyFlightInputs()
        }
        let serverRandom = [UInt8](try secureRandomBytes(count: 32))

        let certMsg = CertificateMessage(certificate: certificate)
        let certBody = certMsg.encode()

        let namedGroup: NamedGroup = .secp256r1
        let keyExchange = try KeyExchange.generate(for: namedGroup)
        s.keyExchange = keyExchange

        let ske = try ServerKeyExchange.create(
            keyExchange: keyExchange,
            signingKey: certificate.signingKey,
            clientRandom: Data(clientHello.random),
            serverRandom: Data(serverRandom)
        )
        let skeBody = ske.encode()

        return DTLSServerHandshake<TLSCryptoProvider>.ServerFlightInputs(
            serverRandom: serverRandom,
            certificateBody: [UInt8](certBody),
            serverKeyExchangeBody: [UInt8](skeBody)
        )
    }

    /// Placeholder inputs for the invalid-cookie path (never sent — the core throws
    /// `cookieMismatch` before they are used).
    private func emptyFlightInputs() throws -> DTLSServerHandshake<TLSCryptoProvider>.ServerFlightInputs {
        DTLSServerHandshake<TLSCryptoProvider>.ServerFlightInputs(
            serverRandom: [UInt8](repeating: 0, count: 32),
            certificateBody: [],
            serverKeyExchangeBody: []
        )
    }

    /// Verify the client's CertificateVerify — proof of possession of the private key
    /// for the certificate it presented (RFC 5246 §7.4.8). Fail-closed.
    private func verifyClientCertificateVerify(
        body: Data,
        handshakeHash: Data,
        state s: inout HandlerState
    ) throws -> Bool {
        guard let certDER = s.fsm.clientCertificateDER else {
            // No certificate to verify against — protocol violation handled by the
            // core's `acceptClientCertificateVerify`.
            return false
        }
        let cv = try CertificateVerify.decode(from: body)
        let verificationKey = try VerificationKey(certificateData: Data(certDER))
        return try cv.verify(handshakeHash: handshakeHash, verificationKey: verificationKey)
    }
}

// MARK: - Typed-throws bridging

/// Runs an FSM call (which throws the closed `DTLSError`) and rethrows. The legacy
/// public API throws untyped `Error` (so callers catch `DTLSError`); this keeps that
/// surface while the core uses typed throws internally. The closure is untyped-throws
/// here (adapter side, not Embedded), so the typed `DTLSError` from the FSM converts
/// cleanly without the closure-inference mismatch that a `throws(DTLSError)` parameter
/// triggers.
@inline(__always)
private func toDTLSError<R>(_ body: () throws -> R) throws -> R {
    try body()
}
