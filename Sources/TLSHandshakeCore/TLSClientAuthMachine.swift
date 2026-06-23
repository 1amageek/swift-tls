/// Embedded-clean TLS 1.3 client post-ServerHello authentication FSM (RFC 8446).
///
/// This is the security-critical slice of the client handshake: from
/// EncryptedExtensions through the server Finished, including the optional mTLS
/// client flight and the application/exporter/resumption secret derivation. It is
/// a value-type, sans-IO, caller-locked finite state machine. It performs **no
/// I/O**, holds **no lock**, and never reaches for a clock — the `TLSCore` adapter
/// owns the `Mutex`, parses wire bytes ↔ Foundation `Data`, runs X.509 / raw
/// public-key trust evaluation, and drives this core under its lock.
///
/// ## Authentication invariants (preserved byte-for-byte)
///
/// - **CertificateVerify proof-of-possession is checked WHENEVER the peer presents
///   a certificate, independent of `verifyPeer`.** `verifyPeer` only gates the
///   adapter's X.509 chain/trust validation; the handshake signature is verified
///   here, in the core, through ``TLSCryptoCore/TLSSignatureVerifier`` — fail
///   closed. If a certificate was presented but no usable public key is available,
///   the handshake aborts (`certificateVerificationFailed`); it never proceeds.
/// - **The CertificateVerify `algorithm` must match the peer key's intrinsic
///   scheme** (`signatureVerificationFailed` otherwise).
/// - **Finished is verified** with a constant-time MAC comparison before any
///   application secret is derived; a mismatch throws `finishedVerificationFailed`.
/// - **Transcript-hash ordering** is owned solely by this core from
///   EncryptedExtensions onward (the adapter must not touch the transcript after
///   handing it over), so transcripts/secrets stay byte-identical.
///
/// No verification failure is ever silently swallowed: every wrong outcome is a
/// typed `TLSHandshakeError` throw (the adapter rethrows it unchanged, so existing
/// tests match the exact case).
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = TLSFoundationProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no ContinuousClock, no swift-crypto, no X509/ASN.1, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore

/// The TLS 1.3 client authentication FSM over the crypto seam.
public struct TLSClientAuthMachine<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// Position in the post-ServerHello authentication flight.
    public enum AuthState: Sendable, Equatable {
        /// Waiting for EncryptedExtensions.
        case waitEncryptedExtensions
        /// Waiting for Certificate or CertificateRequest.
        case waitCertificateOrCertificateRequest
        /// Waiting for Certificate (after a CertificateRequest).
        case waitCertificate
        /// Waiting for CertificateVerify.
        case waitCertificateVerify
        /// Waiting for the server Finished.
        case waitFinished
        /// Server Finished verified; the adapter is assembling the client flight
        /// (Certificate / CertificateVerify) before the client Finished.
        case buildingClientFlight
        /// The handshake is complete.
        case connected
    }

    // MARK: - Stored Fields (all value types)

    /// The running transcript hash. **Owned by this core**; the adapter must not
    /// update it after constructing the machine.
    private var transcript: TLSTranscriptHash<C>

    /// The key schedule, already advanced to the handshake-secret state.
    private var keySchedule: TLSKeySchedule<C>

    /// The negotiated cipher suite.
    public let cipherSuite: CipherSuite

    private var state: AuthState

    private let clientHandshakeSecret: [UInt8]
    private let serverHandshakeSecret: [UInt8]

    private let pskUsed: Bool
    private let verifyPeer: Bool

    /// 0-RTT: whether the client attempted early data and whether the server
    /// accepted it (resolved in EncryptedExtensions).
    private let attemptingEarlyData: Bool
    private var earlyDataAccepted: Bool

    // mTLS request state (server → client CertificateRequest).
    private var clientCertificateRequested: Bool
    private var certificateRequestContext: [UInt8]
    private var peerSignatureAlgorithms: [TLSWireCore.SignatureScheme]?

    // Whether the server's Certificate message carried at least one entry. The
    // peer public key itself is resolved adapter-side (it reads config
    // precedence: `expectedPeerPublicKey` over the certificate key) and handed to
    // ``ingestServerCertificateVerify`` as a parameter.
    private var certificatePresented: Bool

    /// Accumulated `.handshake`-level client flight bytes (client Certificate,
    /// CertificateVerify, Finished) assembled across the Finished-phase steps and
    /// emitted as a single ordered `.send` action by ``finalizeClientFlight``.
    private var clientFlightBytes: [UInt8]

    /// The application-traffic secrets captured by ``ingestServerFinished`` and
    /// emitted by ``finalizeClientFlight`` (kept across the multi-step flight so
    /// the ordering — flight, then application keys, then completion — is exact).
    private var pendingApplicationSecrets: (client: [UInt8], server: [UInt8])?

    /// The application-traffic secrets, captured after a successful handshake so
    /// the adapter can read them back (it stops touching the key schedule once it
    /// hands ownership to this core).
    public private(set) var clientApplicationSecret: [UInt8]?
    public private(set) var serverApplicationSecret: [UInt8]?
    public private(set) var exporterMasterSecret: [UInt8]?

    /// The resumption master secret, returned so the adapter can derive ticket
    /// PSKs post-handshake without retaining the key schedule.
    public private(set) var resumptionMasterSecret: [UInt8]?

    // MARK: - Initialization

    /// Constructs the authentication machine at the EncryptedExtensions boundary.
    ///
    /// The adapter passes ownership of the transcript (already containing
    /// ClientHello…ServerHello) and the key schedule (already advanced to the
    /// handshake secret). For a PSK handshake the starting state skips
    /// Certificate/CertificateVerify.
    ///
    /// - Parameters:
    ///   - transcript: The running transcript hash, CH…SH absorbed.
    ///   - keySchedule: The key schedule at the handshake-secret state.
    ///   - cipherSuite: The negotiated cipher suite.
    ///   - clientHandshakeSecret: `client_handshake_traffic_secret`.
    ///   - serverHandshakeSecret: `server_handshake_traffic_secret`.
    ///   - pskUsed: Whether a PSK was accepted (skips peer authentication).
    ///   - verifyPeer: Adapter trust-validation flag (gates the fail-closed
    ///     "cert but no key" branch when no certificate was sent).
    ///   - attemptingEarlyData: Whether the client offered 0-RTT.
    public init(
        transcript: consuming TLSTranscriptHash<C>,
        keySchedule: consuming TLSKeySchedule<C>,
        cipherSuite: CipherSuite,
        clientHandshakeSecret: [UInt8],
        serverHandshakeSecret: [UInt8],
        pskUsed: Bool,
        verifyPeer: Bool,
        attemptingEarlyData: Bool
    ) {
        self.transcript = transcript
        self.keySchedule = keySchedule
        self.cipherSuite = cipherSuite
        self.clientHandshakeSecret = clientHandshakeSecret
        self.serverHandshakeSecret = serverHandshakeSecret
        self.pskUsed = pskUsed
        self.verifyPeer = verifyPeer
        self.attemptingEarlyData = attemptingEarlyData
        self.earlyDataAccepted = false
        self.clientCertificateRequested = false
        self.certificateRequestContext = []
        self.peerSignatureAlgorithms = nil
        self.certificatePresented = false
        self.clientFlightBytes = []
        self.pendingApplicationSecrets = nil
        self.state = .waitEncryptedExtensions
    }

    // MARK: - Accessors

    /// The current authentication state.
    public var currentState: AuthState { state }

    /// Whether the server requested a client certificate.
    public var clientCertificateWasRequested: Bool { clientCertificateRequested }

    /// Whether the server accepted 0-RTT early data.
    public var earlyDataWasAccepted: Bool { earlyDataAccepted }

    /// The key schedule value (so the adapter can retain it for post-handshake
    /// ticket-PSK derivation).
    public var currentKeySchedule: TLSKeySchedule<C> { keySchedule }

    // MARK: - EncryptedExtensions

    /// Ingests EncryptedExtensions: records 0-RTT acceptance, folds the message
    /// into the transcript, and transitions to the certificate phase (or directly
    /// to Finished for a PSK handshake).
    ///
    /// EncryptedExtensions content-validation that depends on `TLSConfiguration`
    /// (ALPN-not-offered, cert-type-not-offered, etc.) stays in the adapter; this
    /// method takes the already-resolved `earlyDataAccepted` bit and the raw
    /// message bytes.
    ///
    /// - Parameters:
    ///   - rawMessageBytes: The complete EncryptedExtensions handshake message
    ///     (header included) to absorb into the transcript.
    ///   - earlyDataAccepted: Whether the server's EncryptedExtensions carried the
    ///     `early_data` extension.
    /// - Returns: `.earlyDataEnd` when 0-RTT was attempted but rejected.
    public mutating func ingestEncryptedExtensions(
        rawMessageBytes: [UInt8],
        earlyDataAccepted: Bool
    ) throws(TLSHandshakeError) -> [TLSHandshakeAction] {
        guard state == .waitEncryptedExtensions else {
            throw .unexpectedMessage("Unexpected EncryptedExtensions")
        }

        var actions: [TLSHandshakeAction] = []
        if attemptingEarlyData {
            self.earlyDataAccepted = earlyDataAccepted
            if !earlyDataAccepted {
                // 0-RTT was rejected: the client must discard the early-data
                // cryptor and retransmit in 1-RTT.
                actions.append(.earlyDataEnd)
            }
        }

        transcript.update(with: rawMessageBytes.span)

        // PSK handshakes carry no Certificate/CertificateVerify.
        state = pskUsed ? .waitFinished : .waitCertificateOrCertificateRequest
        return actions
    }

    // MARK: - CertificateRequest

    /// Ingests a CertificateRequest (mutual TLS): records the echo context and the
    /// server's offered signature algorithms, folds the message into the
    /// transcript, and waits for the server Certificate.
    public mutating func ingestCertificateRequest(
        _ request: CertificateRequest,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) -> [TLSHandshakeAction] {
        guard state == .waitCertificateOrCertificateRequest else {
            throw .unexpectedMessage("Unexpected CertificateRequest in state \(state)")
        }

        certificateRequestContext = request.certificateRequestContext
        clientCertificateRequested = true
        peerSignatureAlgorithms = request.signatureAlgorithms

        transcript.update(with: rawMessageBytes.span)
        state = .waitCertificate
        return []
    }

    // MARK: - Certificate

    /// Ingests the server Certificate: records whether a certificate was
    /// presented, then folds the message into the transcript.
    ///
    /// The core deliberately receives **bytes**, not a certificate: parsing,
    /// chain building, trust evaluation, AND peer-key selection stay adapter-side
    /// (the adapter reads the config precedence `expectedPeerPublicKey` over the
    /// certificate key). The proof-of-possession signature check happens in
    /// ``ingestServerCertificateVerify``, which receives the resolved key.
    ///
    /// - Parameters:
    ///   - certificatePresented: Whether the peer's Certificate message carried at
    ///     least one entry.
    ///   - rawMessageBytes: The complete Certificate handshake message.
    public mutating func ingestServerCertificate(
        certificatePresented: Bool,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) -> [TLSHandshakeAction] {
        guard state == .waitCertificate || state == .waitCertificateOrCertificateRequest else {
            throw .unexpectedMessage("Unexpected Certificate")
        }

        self.certificatePresented = certificatePresented

        transcript.update(with: rawMessageBytes.span)
        state = .waitCertificateVerify
        return []
    }

    // MARK: - CertificateVerify

    /// Ingests the server CertificateVerify and performs the **proof-of-possession
    /// signature check** through ``TLSCryptoCore/TLSSignatureVerifier``.
    ///
    /// This is the heart of the auth invariant: the signature is verified whenever
    /// a certificate was presented, independent of `verifyPeer`. The peer key's
    /// intrinsic scheme must match the CertificateVerify `algorithm`. If a
    /// certificate was presented but no usable key is available, the handshake
    /// aborts. On success the message is folded into the transcript and the
    /// adapter is asked to run its (Foundation/closure) certificate validator
    /// before the server Finished is processed.
    ///
    /// - Parameters:
    ///   - certificateVerify: The decoded CertificateVerify message.
    ///   - peerPublicKey: The resolved peer public-key bytes (x963 for the NIST
    ///     curves, raw for Ed25519) and the key's intrinsic signature scheme, or
    ///     `nil` if the adapter could not produce one. Resolution precedence
    ///     (`expectedPeerPublicKey` over the certificate key) is the adapter's
    ///     responsibility.
    ///   - rawMessageBytes: The complete CertificateVerify handshake message.
    /// - Returns: `.runCertificateValidator` so the adapter runs its
    ///   `certificateValidator` closure on the raw peer certificates (libp2p
    ///   PeerID extraction). The adapter MUST propagate any validator error and
    ///   NOT call ``ingestServerFinished`` if it throws.
    public mutating func ingestServerCertificateVerify(
        _ certificateVerify: CertificateVerify,
        peerPublicKey: (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)?,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) -> [TLSHandshakeAction] {
        guard state == .waitCertificateVerify else {
            throw .unexpectedMessage("Unexpected CertificateVerify")
        }

        // Transcript hash up to (but not including) CertificateVerify.
        let transcriptHash = transcript.currentHash()

        if let key = peerPublicKey {
            // The CertificateVerify algorithm must match the key's own scheme.
            guard key.scheme == certificateVerify.algorithm else {
                throw .signatureVerificationFailed
            }

            let isValid: Bool
            do {
                isValid = try TLSSignatureVerifier<C>.verify(
                    signature: certificateVerify.signature.span,
                    algorithm: certificateVerify.algorithm,
                    publicKeyBytes: key.bytes.span,
                    transcriptHash: transcriptHash.span,
                    isServer: true
                )
            } catch {
                // An unsupported scheme or a key-import failure is a verification
                // failure — never a silent accept.
                throw .signatureVerificationFailed
            }

            guard isValid else {
                throw .signatureVerificationFailed
            }
        } else if certificatePresented || verifyPeer {
            // A certificate (or CertificateVerify) was presented but no key is
            // available to verify possession. Fail closed.
            throw .certificateVerificationFailed(
                "No public key available to verify CertificateVerify"
            )
        }

        transcript.update(with: rawMessageBytes.span)
        state = .waitFinished
        return [.runCertificateValidator]
    }

    // MARK: - Server Finished

    /// Ingests the server Finished and verifies its MAC, then derives the
    /// application + exporter secrets.
    ///
    /// Steps (byte-identical to the pre-FSM implementation):
    /// 1. Verify the server Finished MAC (constant time); abort on mismatch.
    /// 2. Fold the server Finished into the transcript.
    /// 3. Derive application + exporter secrets (captured for emission later).
    /// 4. If 0-RTT was accepted, emit EndOfEarlyData (absorbed into the transcript)
    ///    and `.earlyDataEnd`.
    ///
    /// After this the adapter assembles the client flight: for a mutual-TLS
    /// handshake it builds the client Certificate (and signs the CertificateVerify
    /// with `any TLSSigningKey`, which must stay adapter-side), feeding the bytes
    /// back through ``foldClientCertificate(messageBytes:)`` /
    /// ``foldClientCertificateVerify(messageBytes:)``; then it calls
    /// ``finalizeClientFlight(alpn:)`` to build the client Finished and emit the
    /// combined flight + application keys + completion in order.
    ///
    /// - Returns: any EndOfEarlyData / `.earlyDataEnd` actions (the application
    ///   keys and completion are emitted by ``finalizeClientFlight(alpn:)``).
    public mutating func ingestServerFinished(
        _ finished: Finished
    ) throws(TLSHandshakeError) -> [TLSHandshakeAction] {
        guard state == .waitFinished else {
            throw .unexpectedMessage("Unexpected Finished in state \(state)")
        }

        // 1. Verify server Finished MAC.
        let serverFinishedKey: [UInt8]
        do {
            serverFinishedKey = try keySchedule.finishedKey(from: serverHandshakeSecret)
        } catch {
            throw .internalError("Failed to derive server finished key")
        }
        let serverFinishedTranscript = transcript.currentHash()
        let expectedVerifyData = keySchedule.finishedVerifyData(
            forKey: serverFinishedKey,
            transcriptHash: serverFinishedTranscript
        )
        guard finished.verify(expected: expectedVerifyData) else {
            throw .finishedVerificationFailed
        }

        // 2. Fold server Finished into the transcript.
        let serverFinishedMessage = finished.encodeAsHandshakeBytes()
        transcript.update(with: serverFinishedMessage.span)

        // 3. Derive application + exporter secrets.
        let appTranscriptHash = transcript.currentHash()
        let appSecrets: (client: [UInt8], server: [UInt8])
        do {
            appSecrets = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscriptHash)
        } catch {
            throw .internalError("Failed to derive application secrets")
        }
        clientApplicationSecret = appSecrets.client
        serverApplicationSecret = appSecrets.server
        pendingApplicationSecrets = appSecrets

        do {
            exporterMasterSecret = try keySchedule.deriveExporterMasterSecret(
                transcriptHash: appTranscriptHash
            )
        } catch {
            throw .internalError("Failed to derive exporter master secret")
        }

        var actions: [TLSHandshakeAction] = []

        // 4. EndOfEarlyData (RFC 8446 §4.5) — emitted before the client flight,
        // encrypted with the early-data keys, and folded into the transcript.
        if earlyDataAccepted {
            let eoed = EndOfEarlyData()
            let eoedMessage = HandshakeCodec.encodeBytes(
                type: .endOfEarlyData,
                content: eoed.encodeBytes()
            )
            transcript.update(with: eoedMessage.span)
            actions.append(.send(bytes: eoedMessage, level: .earlyData))
            actions.append(.earlyDataEnd)
        }

        state = .buildingClientFlight
        return actions
    }

    // MARK: - Client mTLS flight (signing is adapter-side)

    /// Folds the adapter-built client Certificate message into the transcript and
    /// accumulates it into the client flight, returning the transcript hash the
    /// client CertificateVerify must be signed over (i.e. the transcript up to but
    /// not including the CertificateVerify). For an empty Certificate the adapter
    /// ignores the returned hash and does not send a CertificateVerify.
    ///
    /// Signing stays adapter-side so any `any TLSSigningKey` conformer (including
    /// HSM-backed / custom keys) is supported; the core only owns the transcript.
    public mutating func foldClientCertificate(
        messageBytes: [UInt8]
    ) throws(TLSHandshakeError) -> [UInt8] {
        guard state == .buildingClientFlight else {
            throw .internalError("Client Certificate folded out of order")
        }
        transcript.update(with: messageBytes.span)
        clientFlightBytes.append(contentsOf: messageBytes)
        return transcript.currentHash()
    }

    /// Folds the adapter-built client CertificateVerify message into the transcript
    /// and accumulates it into the client flight.
    public mutating func foldClientCertificateVerify(
        messageBytes: [UInt8]
    ) throws(TLSHandshakeError) {
        guard state == .buildingClientFlight else {
            throw .internalError("Client CertificateVerify folded out of order")
        }
        transcript.update(with: messageBytes.span)
        clientFlightBytes.append(contentsOf: messageBytes)
    }

    /// Builds the client Finished, concatenates the full `.handshake` flight
    /// (client Certificate / CertificateVerify accumulated earlier, then Finished),
    /// folds the client Finished into the transcript, derives the resumption
    /// secret, and emits the flight + application keys + completion in order.
    ///
    /// - Parameter alpn: The negotiated ALPN protocol, echoed in completion.
    public mutating func finalizeClientFlight(
        alpn: String?
    ) throws(TLSHandshakeError) -> [TLSHandshakeAction] {
        guard state == .buildingClientFlight else {
            throw .internalError("Client flight finalized out of order")
        }
        guard let appSecrets = pendingApplicationSecrets else {
            throw .internalError("Missing application secrets")
        }

        // Client Finished.
        let clientFinishedKey: [UInt8]
        do {
            clientFinishedKey = try keySchedule.finishedKey(from: clientHandshakeSecret)
        } catch {
            throw .internalError("Failed to derive client finished key")
        }
        let clientFinishedTranscript = transcript.currentHash()
        let clientVerifyData = keySchedule.finishedVerifyData(
            forKey: clientFinishedKey,
            transcriptHash: clientFinishedTranscript
        )
        let clientFinished = Finished(verifyData: clientVerifyData)
        let clientFinishedMessage = clientFinished.encodeAsHandshakeBytes()

        var flight = clientFlightBytes
        flight.append(contentsOf: clientFinishedMessage)

        var actions: [TLSHandshakeAction] = []
        actions.append(.send(bytes: flight, level: .handshake))

        // Fold client Finished into the transcript, then derive resumption secret.
        transcript.update(with: clientFinishedMessage.span)
        let resumptionTranscriptHash = transcript.currentHash()
        do {
            resumptionMasterSecret = try keySchedule.deriveResumptionMasterSecret(
                transcriptHash: resumptionTranscriptHash
            )
        } catch {
            throw .internalError("Failed to derive resumption master secret")
        }

        state = .connected
        clientFlightBytes = []

        actions.append(.secretsAvailable(TLSHandshakeSecrets(
            level: .application,
            client: appSecrets.client,
            server: appSecrets.server,
            cipherSuite: cipherSuite
        )))
        actions.append(.handshakeComplete(alpn: alpn, zeroRTTAccepted: earlyDataAccepted))

        return actions
    }
}
