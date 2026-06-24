/// Embedded-clean TLS 1.3 server handshake FSM (RFC 8446).
///
/// The server-side analogue of ``TLSClientHandshake`` + ``TLSClientAuthMachine``:
/// a single value-type, sans-IO, caller-locked finite state machine spanning
/// ClientHello ingestion through the client Finished. It performs **no I/O**, holds
/// **no lock**, and never reaches for a clock — the `TLSCore` adapter owns the
/// `Mutex`, parses wire bytes ↔ Foundation `Data`, runs `TLSConfiguration`-dependent
/// negotiation (cipher suite, groups, ALPN, cert types), X.509 / raw-public-key
/// trust evaluation, the X25519MLKEM768 hybrid KEM, and the `any TLSSigningKey`
/// CertificateVerify signing, and drives this core under its lock.
///
/// ## Security invariants (preserved byte-for-byte)
///
/// - **PSK-binder validation** is `finishedVerifyData` over the truncated-ClientHello
///   transcript hash compared constant-time against the offered binder; a mismatch
///   means the PSK is not accepted (the adapter falls back to a full handshake),
///   never a silent accept of an unauthenticated PSK.
/// - **Client CertificateVerify proof-of-possession is verified through
///   ``TLSCryptoCore/TLSSignatureVerifier``, fail-closed.** The CertificateVerify
///   `algorithm` must match the client key's intrinsic scheme; an invalid signature
///   or a key-import failure throws (`signatureVerificationFailed`), never proceeds.
/// - **Client Finished is verified** with a constant-time MAC before the resumption
///   secret is derived; a mismatch throws `finishedVerificationFailed`.
/// - **Transcript ordering** is owned solely by this core; HRR uses the RFC 8446
///   §4.4.1 `message_hash` synthetic transform so transcripts/secrets stay
///   byte-identical.
///
/// ## What stays adapter-side
///
/// - `TLSConfiguration`-dependent negotiation and *wire-extension assembly* (the
///   adapter hands the core the finished ServerHello / EncryptedExtensions /
///   CertificateRequest extension lists).
/// - The X25519MLKEM768 hybrid (KEM, not expressible through the DH seam): the
///   adapter computes the server share + shared secret and passes them in. Pure-DH
///   groups are agreed in-core through ``TLSCryptoCore/TLSKeyExchange``.
/// - The server CertificateVerify *signing* (`any TLSSigningKey`, including HSM /
///   custom keys): the core hands out the transcript hash to sign over and the
///   adapter folds the signed CertificateVerify bytes back.
/// - X.509 parsing / chain / trust and the `certificateValidator` closure.
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = TLSCryptoProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no ContinuousClock, no swift-crypto, no X509/ASN.1, typed throws, no key paths.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore

/// The TLS 1.3 server handshake FSM over the crypto seam.
public struct TLSServerHandshake<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// Position in the server flight.
    public enum ServerState: Sendable, Equatable {
        /// Before any ClientHello has been ingested.
        case start
        /// HelloRetryRequest sent; waiting for ClientHello2.
        case sentHelloRetryRequest
        /// ServerHello…Finished flight built; waiting for the client Certificate
        /// (mutual TLS).
        case waitClientCertificate
        /// Waiting for the client CertificateVerify (mutual TLS).
        case waitClientCertificateVerify
        /// Waiting for the client Finished.
        case waitFinished
        /// The handshake is complete.
        case connected
    }

    // MARK: - Stored Fields (all value types)

    /// The running transcript hash. **Owned by this core.**
    private var transcript: TLSTranscriptHash<C>

    /// The key schedule.
    private var keySchedule: TLSKeySchedule<C>

    /// The negotiated cipher suite.
    private var cipherSuite: CipherSuite

    private var state: ServerState

    private var clientHandshakeSecret: [UInt8]?
    private var serverHandshakeSecret: [UInt8]?

    private var pskUsed: Bool

    // mTLS verification state: the client CertificateVerify algorithm must be one
    // the server offered in CertificateRequest.signature_algorithms.
    private var sentSignatureAlgorithms: [TLSWireCore.SignatureScheme]?
    private var requestedClientCertificate: Bool

    /// Captured secrets read back by the adapter post-handshake.
    public private(set) var clientApplicationSecret: [UInt8]?
    public private(set) var serverApplicationSecret: [UInt8]?
    public private(set) var exporterMasterSecret: [UInt8]?
    public private(set) var resumptionMasterSecret: [UInt8]?

    // MARK: - Initialization

    /// Constructs a fresh server FSM in the `start` state for the given provisional
    /// cipher suite (the suite is re-fixed when ClientHello negotiation resolves it).
    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        self.transcript = TLSTranscriptHash<C>(cipherSuite: cipherSuite)
        self.keySchedule = TLSKeySchedule<C>(cipherSuite: cipherSuite)
        self.cipherSuite = cipherSuite
        self.state = .start
        self.clientHandshakeSecret = nil
        self.serverHandshakeSecret = nil
        self.pskUsed = false
        self.sentSignatureAlgorithms = nil
        self.requestedClientCertificate = false
    }

    // MARK: - Accessors

    /// The current server state.
    public var currentState: ServerState { state }

    /// The negotiated (or provisional) cipher suite.
    public var negotiatedCipherSuite: CipherSuite { cipherSuite }

    /// Whether a PSK was accepted.
    public var pskWasUsed: Bool { pskUsed }

    // MARK: - PSK binder validation

    /// Validates a PSK binder against the truncated ClientHello.
    ///
    /// Derives the early secret from `psk`, the binder key from it, and compares the
    /// resulting `finishedVerifyData` over the truncated-ClientHello transcript hash
    /// against the offered binder in constant time. The transcript hash is computed
    /// with `cipherSuite`'s hash. Used during ClientHello processing (which is fully
    /// adapter-driven for negotiation); the binder check itself is security-critical
    /// and lives here so the seam HMAC path is exercised.
    ///
    /// - Returns: `true` iff the binder is valid (the adapter then accepts the PSK);
    ///   `false` otherwise (the adapter continues with a full handshake — never a
    ///   silent accept).
    public static func isValidPSKBinder(
        psk: [UInt8],
        cipherSuite: CipherSuite,
        truncatedClientHello: [UInt8],
        offeredBinder: [UInt8],
        isResumption: Bool
    ) throws(TLSHandshakeError) -> Bool {
        var schedule = TLSKeySchedule<C>(cipherSuite: cipherSuite)
        schedule.deriveEarlySecret(psk: psk)

        let binderKey: [UInt8]
        do {
            binderKey = try schedule.deriveBinderKey(isResumption: isResumption)
        } catch {
            throw .internalError("Failed to derive PSK binder key")
        }
        let finishedKey: [UInt8]
        do {
            finishedKey = try schedule.finishedKey(from: binderKey)
        } catch {
            throw .internalError("Failed to derive PSK binder finished key")
        }

        var transcript = TLSTranscriptHash<C>(cipherSuite: cipherSuite)
        transcript.update(with: truncatedClientHello.span)
        let expected = schedule.finishedVerifyData(
            forKey: finishedKey,
            transcriptHash: transcript.currentHash()
        )
        return constantTimeEqual(expected, offeredBinder)
    }

    // MARK: - HelloRetryRequest

    /// Applies the RFC 8446 §4.4.1 HelloRetryRequest transcript transform: folds
    /// ClientHello1 into the transcript, replaces it with the `message_hash`
    /// synthetic message of ClientHello1, and folds the HRR into it. Fixes the
    /// negotiated cipher suite. Only one HRR is permitted.
    ///
    /// - Parameters:
    ///   - cipherSuite: The negotiated cipher suite (carried into ClientHello2).
    ///   - clientHello1Bytes: The complete ClientHello1 handshake message.
    ///   - helloRetryRequestBytes: The complete HelloRetryRequest handshake message.
    public mutating func applyHelloRetryRequest(
        cipherSuite: CipherSuite,
        clientHello1Bytes: [UInt8],
        helloRetryRequestBytes: [UInt8]
    ) throws(TLSHandshakeError) {
        guard state == .start else {
            throw .unexpectedMessage("Multiple HelloRetryRequest not allowed")
        }
        self.cipherSuite = cipherSuite

        transcript = TLSTranscriptHash<C>(cipherSuite: cipherSuite)
        transcript.update(with: clientHello1Bytes.span)
        let ch1Hash = transcript.currentHash()
        transcript = TLSTranscriptHash<C>.fromMessageHash(
            clientHello1Hash: ch1Hash,
            cipherSuite: cipherSuite
        )
        transcript.update(with: helloRetryRequestBytes.span)
        state = .sentHelloRetryRequest
    }

    // MARK: - ClientHello → server flight

    /// The (EC)DHE input for the server flight. For a pure-DH group the core agrees
    /// the secret through ``TLSCryptoCore/TLSKeyExchange``; for the X25519MLKEM768
    /// hybrid (KEM) the adapter encapsulates and passes the shared secret.
    public enum KeyExchangeInput: Sendable {
        case agree(group: NamedGroup, privateKeyBytes: [UInt8], peerPublicKeyBytes: [UInt8])
        case precomputed([UInt8])
    }

    /// Accepted-PSK material: the resolved PSK bytes and the ticket's cipher suite
    /// (the early-secret hash). The adapter validates the binder (via
    /// ``isValidPSKBinder``) and resolves the session before passing this in; the
    /// core then installs the PSK early secret into the key schedule.
    public struct AcceptedPSK: Sendable {
        public let psk: [UInt8]
        public let cipherSuite: CipherSuite
        public init(psk: [UInt8], cipherSuite: CipherSuite) {
            self.psk = psk
            self.cipherSuite = cipherSuite
        }
    }

    /// The server's resolved per-handshake parameters for building the flight. The
    /// adapter computes all negotiation outcomes (which depend on `TLSConfiguration`)
    /// and hands them here; the core owns the transcript + key schedule + crypto.
    public struct FlightParameters: Sendable {
        /// The negotiated cipher suite.
        public let cipherSuite: CipherSuite
        /// The accepted PSK (skips Certificate/CertificateVerify), or `nil`.
        public let acceptedPSK: AcceptedPSK?
        /// The (EC)DHE input.
        public let keyExchange: KeyExchangeInput
        /// Whether 0-RTT early data was accepted (drives the 0-RTT-secret derivation).
        public let earlyDataAccepted: Bool
        /// Whether the server requested a client certificate (mutual TLS).
        public let requestClientCertificate: Bool
        /// The signature algorithms offered in CertificateRequest (validated against
        /// the client CertificateVerify later), or `nil` if no CR is sent.
        public let certificateRequestSignatureAlgorithms: [TLSWireCore.SignatureScheme]?

        public init(
            cipherSuite: CipherSuite,
            acceptedPSK: AcceptedPSK?,
            keyExchange: KeyExchangeInput,
            earlyDataAccepted: Bool,
            requestClientCertificate: Bool,
            certificateRequestSignatureAlgorithms: [TLSWireCore.SignatureScheme]?
        ) {
            self.cipherSuite = cipherSuite
            self.acceptedPSK = acceptedPSK
            self.keyExchange = keyExchange
            self.earlyDataAccepted = earlyDataAccepted
            self.requestClientCertificate = requestClientCertificate
            self.certificateRequestSignatureAlgorithms = certificateRequestSignatureAlgorithms
        }
    }

    /// A request for the adapter to sign the server CertificateVerify over
    /// `transcriptHash` with its `any TLSSigningKey` and feed the signed bytes back
    /// via ``foldServerCertificateVerify(messageBytes:)``. Signing stays adapter-side
    /// so any signing-key conformer (incl. HSM / custom) is supported.
    public struct ServerCertificateVerifyRequest: Sendable, Equatable {
        public let transcriptHash: [UInt8]
        public init(transcriptHash: [UInt8]) {
            self.transcriptHash = transcriptHash
        }
    }

    /// Begins the server flight: ingests ClientHello, agrees the (EC)DHE secret,
    /// folds ClientHello + ServerHello into the transcript, derives the handshake
    /// secrets, emits handshake-level keys, and (for a PSK handshake, or after the
    /// caller folds the server Certificate/CertificateVerify) continues toward
    /// EncryptedExtensions.
    ///
    /// The caller supplies the assembled wire messages (ServerHello,
    /// EncryptedExtensions, optional CertificateRequest, and — for a non-PSK
    /// handshake — Certificate). The core folds them in transcript order and, for a
    /// non-PSK handshake, returns a ``ServerCertificateVerifyRequest`` for the
    /// adapter to sign; the adapter then calls ``foldServerCertificateVerify`` and
    /// ``finishServerFlight`` to emit the CertificateVerify + Finished + application
    /// keys. PSK handshakes skip straight to ``finishServerFlight``.
    ///
    /// - Parameters:
    ///   - clientHelloBytes: The complete ClientHello handshake message.
    ///   - parameters: The adapter-resolved negotiation outcomes.
    ///   - serverHelloBytes: The assembled ServerHello handshake message.
    ///   - encryptedExtensionsBytes: The assembled EncryptedExtensions message.
    ///   - certificateRequestBytes: The assembled CertificateRequest message (mTLS),
    ///     or `nil`.
    ///   - serverCertificateBytes: The assembled server Certificate message
    ///     (non-PSK), or `nil` for a PSK handshake.
    /// - Returns: the handshake-traffic secrets, and — for a non-PSK handshake — the
    ///   CertificateVerify signing request.
    public mutating func beginServerFlight(
        clientHelloBytes: [UInt8],
        parameters: FlightParameters,
        serverHelloBytes: [UInt8],
        encryptedExtensionsBytes: [UInt8],
        certificateRequestBytes: [UInt8]?,
        serverCertificateBytes: [UInt8]?
    ) throws(TLSHandshakeError) -> (
        handshakeSecrets: (client: [UInt8], server: [UInt8]),
        clientEarlyTrafficSecret: [UInt8]?,
        certificateVerifyRequest: ServerCertificateVerifyRequest?
    ) {
        guard state == .start || state == .sentHelloRetryRequest else {
            throw .unexpectedMessage("Unexpected ClientHello in state \(state)")
        }

        self.cipherSuite = parameters.cipherSuite
        self.pskUsed = parameters.acceptedPSK != nil
        self.requestedClientCertificate = parameters.requestClientCertificate
        self.sentSignatureAlgorithms = parameters.certificateRequestSignatureAlgorithms

        // Compute the (EC)DHE shared secret.
        let sharedSecret: [UInt8]
        switch parameters.keyExchange {
        case .agree(let group, let privateKeyBytes, let peerPublicKeyBytes):
            do {
                sharedSecret = try TLSKeyExchange<C>.sharedSecret(
                    group: group,
                    privateKeyBytes: privateKeyBytes.span,
                    peerPublicKeyBytes: peerPublicKeyBytes.span
                )
            } catch {
                throw .keyExchangeFailed("(EC)DHE failed: \(error)")
            }
        case .precomputed(let secret):
            sharedSecret = secret
        }

        // Install the early secret: from the PSK (at the ticket suite) for an
        // accepted PSK, else fresh at the negotiated suite. The main transcript
        // keeps its own (default) suite, matching the legacy adapter.
        if let acceptedPSK = parameters.acceptedPSK {
            keySchedule = TLSKeySchedule<C>(cipherSuite: acceptedPSK.cipherSuite)
            keySchedule.deriveEarlySecret(psk: acceptedPSK.psk)
        } else {
            keySchedule = TLSKeySchedule<C>(cipherSuite: parameters.cipherSuite)
            keySchedule.deriveEarlySecret(psk: nil)
        }

        // Fold ClientHello. After a HelloRetryRequest the transcript already carries
        // message_hash(CH1) + HRR, and `clientHelloBytes` is ClientHello2; before an
        // HRR it is the sole ClientHello.
        transcript.update(with: clientHelloBytes.span)

        // 0-RTT: the client_early_traffic_secret is derived over the *main*
        // transcript hash at the ClientHello-only point (default suite), matching the
        // legacy server adapter (which uses `state.context.transcriptHash`, not a
        // fresh ticket-suite transcript).
        var clientEarlyTrafficSecret: [UInt8]?
        if parameters.earlyDataAccepted, parameters.acceptedPSK != nil {
            do {
                clientEarlyTrafficSecret = try keySchedule.deriveClientEarlyTrafficSecret(
                    transcriptHash: transcript.currentHash()
                )
            } catch {
                throw .internalError("Failed to derive client early traffic secret")
            }
        }

        // Fold ServerHello, then derive the handshake-traffic secrets over CH…SH.
        transcript.update(with: serverHelloBytes.span)
        let handshakeSecrets: (client: [UInt8], server: [UInt8])
        do {
            handshakeSecrets = try keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcript.currentHash()
            )
        } catch {
            throw .internalError("Failed to derive handshake secrets")
        }
        clientHandshakeSecret = handshakeSecrets.client
        serverHandshakeSecret = handshakeSecrets.server

        // EncryptedExtensions.
        transcript.update(with: encryptedExtensionsBytes.span)

        // CertificateRequest (mutual TLS).
        if let certificateRequestBytes {
            transcript.update(with: certificateRequestBytes.span)
        }

        // Non-PSK: fold the server Certificate and request a CertificateVerify
        // signature over the current transcript hash.
        var certificateVerifyRequest: ServerCertificateVerifyRequest?
        if parameters.acceptedPSK == nil {
            guard let serverCertificateBytes else {
                throw .internalError("Non-PSK handshake missing server Certificate")
            }
            transcript.update(with: serverCertificateBytes.span)
            certificateVerifyRequest = ServerCertificateVerifyRequest(
                transcriptHash: transcript.currentHash()
            )
        }

        return (handshakeSecrets, clientEarlyTrafficSecret, certificateVerifyRequest)
    }

    /// Folds the adapter-signed server CertificateVerify into the transcript.
    /// Called only for a non-PSK handshake, after ``beginServerFlight`` returned a
    /// signing request.
    public mutating func foldServerCertificateVerify(
        messageBytes: [UInt8]
    ) throws(TLSHandshakeError) {
        guard state == .start || state == .sentHelloRetryRequest else {
            throw .internalError("Server CertificateVerify folded out of order")
        }
        transcript.update(with: messageBytes.span)
    }

    /// Builds the server Finished, folds it into the transcript, derives the
    /// application + exporter secrets, and transitions to the wait-for-client phase.
    ///
    /// - Returns: the server Finished handshake-message bytes and the application +
    ///   exporter secrets. The adapter sends the Finished (and the earlier flight)
    ///   and installs the application keys.
    public mutating func finishServerFlight() throws(TLSHandshakeError) -> (
        serverFinished: [UInt8],
        applicationSecrets: (client: [UInt8], server: [UInt8]),
        exporterMasterSecret: [UInt8]
    ) {
        guard state == .start || state == .sentHelloRetryRequest else {
            throw .internalError("Server flight finished out of order")
        }
        guard let serverHandshakeSecret else {
            throw .internalError("Missing server handshake secret")
        }

        // Server Finished.
        let serverFinishedKey: [UInt8]
        do {
            serverFinishedKey = try keySchedule.finishedKey(from: serverHandshakeSecret)
        } catch {
            throw .internalError("Failed to derive server finished key")
        }
        let verifyData = keySchedule.finishedVerifyData(
            forKey: serverFinishedKey,
            transcriptHash: transcript.currentHash()
        )
        let serverFinished = Finished(verifyData: verifyData)
        let serverFinishedMessage = serverFinished.encodeAsHandshakeBytes()
        transcript.update(with: serverFinishedMessage.span)

        // Application + exporter secrets over CH…server Finished.
        let appTranscriptHash = transcript.currentHash()
        let appSecrets: (client: [UInt8], server: [UInt8])
        do {
            appSecrets = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscriptHash)
        } catch {
            throw .internalError("Failed to derive application secrets")
        }
        clientApplicationSecret = appSecrets.client
        serverApplicationSecret = appSecrets.server

        let exporter: [UInt8]
        do {
            exporter = try keySchedule.deriveExporterMasterSecret(transcriptHash: appTranscriptHash)
        } catch {
            throw .internalError("Failed to derive exporter master secret")
        }
        exporterMasterSecret = exporter

        state = requestedClientCertificate ? .waitClientCertificate : .waitFinished
        return (serverFinishedMessage, appSecrets, exporter)
    }

    // MARK: - 0-RTT EndOfEarlyData

    /// Folds a client EndOfEarlyData message (RFC 8446 §4.5) into the transcript.
    /// The adapter validates the message body and gates this on early-data
    /// acceptance.
    public mutating func ingestEndOfEarlyData(
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) {
        transcript.update(with: rawMessageBytes.span)
    }

    // MARK: - Client Certificate (mutual TLS)

    /// Ingests the client Certificate: records whether a certificate was presented
    /// and folds the message into the transcript. Parsing / trust stays adapter-side
    /// (the resolved peer key arrives at ``ingestClientCertificateVerify``).
    ///
    /// - Parameters:
    ///   - certificatePresented: Whether the client's Certificate carried an entry.
    ///   - rawMessageBytes: The complete client Certificate handshake message.
    /// - Returns: `true` if a CertificateVerify is expected next (a certificate was
    ///   presented); `false` if the client sent an empty Certificate (the next
    ///   message is the client Finished).
    public mutating func ingestClientCertificate(
        certificatePresented: Bool,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) -> Bool {
        guard state == .waitClientCertificate else {
            throw .unexpectedMessage("Unexpected client Certificate")
        }
        transcript.update(with: rawMessageBytes.span)
        if certificatePresented {
            state = .waitClientCertificateVerify
            return true
        } else {
            state = .waitFinished
            return false
        }
    }

    /// Ingests the client CertificateVerify and performs the **proof-of-possession
    /// signature check** through ``TLSCryptoCore/TLSSignatureVerifier``, fail-closed.
    ///
    /// The CertificateVerify `algorithm` must be one offered in the
    /// CertificateRequest and must match the client key's intrinsic scheme. An
    /// invalid signature, a scheme mismatch, or a missing key throws — never
    /// proceeds. The signature is verified over the transcript up to (not including)
    /// the CertificateVerify; the message is folded in afterward.
    ///
    /// - Parameters:
    ///   - certificateVerify: The decoded client CertificateVerify.
    ///   - clientPublicKey: The resolved client public-key bytes and intrinsic
    ///     scheme, or `nil` if the adapter could not produce one.
    ///   - rawMessageBytes: The complete CertificateVerify handshake message.
    public mutating func ingestClientCertificateVerify(
        _ certificateVerify: CertificateVerify,
        clientPublicKey: (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)?,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) {
        guard state == .waitClientCertificateVerify else {
            throw .unexpectedMessage("Unexpected client CertificateVerify")
        }

        // The algorithm must be one the server offered in CertificateRequest.
        if let sentAlgs = sentSignatureAlgorithms {
            guard sentAlgs.contains(certificateVerify.algorithm) else {
                throw .signatureVerificationFailed
            }
        }

        guard let key = clientPublicKey else {
            throw .internalError("Missing client verification key")
        }
        // The CertificateVerify algorithm must match the key's own scheme.
        guard key.scheme == certificateVerify.algorithm else {
            throw .signatureVerificationFailed
        }

        // Transcript hash up to (not including) CertificateVerify.
        let transcriptHash = transcript.currentHash()
        let isValid: Bool
        do {
            isValid = try TLSSignatureVerifier<C>.verify(
                signature: certificateVerify.signature.span,
                algorithm: certificateVerify.algorithm,
                publicKeyBytes: key.bytes.span,
                transcriptHash: transcriptHash.span,
                isServer: false  // CLIENT CertificateVerify
            )
        } catch {
            throw .signatureVerificationFailed
        }
        guard isValid else {
            throw .signatureVerificationFailed
        }

        transcript.update(with: rawMessageBytes.span)
        state = .waitFinished
    }

    // MARK: - Client Finished

    /// Ingests the client Finished, verifies its MAC (constant time, fail-closed),
    /// folds it into the transcript, and derives the resumption master secret.
    ///
    /// - Parameter finished: The decoded client Finished.
    public mutating func ingestClientFinished(
        _ finished: Finished
    ) throws(TLSHandshakeError) {
        guard state == .waitFinished else {
            throw .unexpectedMessage("Unexpected client Finished")
        }
        guard let clientHandshakeSecret else {
            throw .internalError("Missing client handshake secret")
        }

        let clientFinishedKey: [UInt8]
        do {
            clientFinishedKey = try keySchedule.finishedKey(from: clientHandshakeSecret)
        } catch {
            throw .internalError("Failed to derive client finished key")
        }
        let expected = keySchedule.finishedVerifyData(
            forKey: clientFinishedKey,
            transcriptHash: transcript.currentHash()
        )
        guard finished.verify(expected: expected) else {
            throw .finishedVerificationFailed
        }

        // Fold the client Finished, then derive the resumption secret.
        let clientFinishedMessage = finished.encodeAsHandshakeBytes()
        transcript.update(with: clientFinishedMessage.span)
        do {
            resumptionMasterSecret = try keySchedule.deriveResumptionMasterSecret(
                transcriptHash: transcript.currentHash()
            )
        } catch {
            throw .internalError("Failed to derive resumption master secret")
        }
        state = .connected
    }

    /// The key schedule value, so the adapter can derive ticket PSKs post-handshake.
    public var currentKeySchedule: TLSKeySchedule<C> { keySchedule }
}
