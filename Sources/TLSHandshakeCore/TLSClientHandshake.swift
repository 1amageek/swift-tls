/// Embedded-clean TLS 1.3 client pre-ServerHello FSM (RFC 8446).
///
/// This is the first slice of the client handshake: ClientHello assembly
/// (including the PSK-binder computation and the 0-RTT early-traffic-secret
/// derivation) and ServerHello / HelloRetryRequest processing (negotiated-group
/// (EC)DHE, handshake-secret derivation, the RFC 8446 §4.1.3 downgrade-sentinel
/// protection, and the transcript bookkeeping). It is a value-type, sans-IO,
/// caller-locked finite state machine. It performs **no I/O**, holds **no lock**,
/// and never reaches for a clock — the `TLSCore` adapter owns the `Mutex`, parses
/// wire bytes ↔ Foundation `Data`, runs `TLSConfiguration`-dependent extension
/// negotiation and X.509 / raw-public-key trust evaluation, and drives this core
/// under its lock.
///
/// ## Security invariants (preserved byte-for-byte)
///
/// - **Downgrade-sentinel detection (RFC 8446 §4.1.3) lives here, fail-closed.**
///   A genuine TLS 1.3 server sets the last 8 bytes of its ServerHello.random to a
///   sentinel ONLY when it negotiated a lower version. Since the client negotiates
///   TLS 1.3, observing either sentinel means an attacker forced a downgrade — the
///   core throws ``TLSWireCore/TLSHandshakeError/downgradeDetected`` (no silent
///   fallback). The sentinel bytes are byte-identical to the legacy adapter
///   constants.
/// - **Transcript ordering** is owned by this core from ClientHello onward; the
///   handshake secret is derived over the exact ClientHello…ServerHello transcript,
///   so secrets stay byte-identical.
/// - **PSK-binder correctness**: the binder is `finishedVerifyData` over the
///   truncated-ClientHello transcript hash, identical to the legacy two-pass build.
///
/// ## What stays adapter-side
///
/// - `TLSConfiguration`-dependent extension selection (ALPN, SNI, cert types,
///   transport parameters) and ClientHello *extension assembly* (the adapter hands
///   the core the finished extension list).
/// - The X25519MLKEM768 hybrid key exchange (a KEM that has no place in the DH-only
///   key-agreement seam): the adapter computes that shared secret and passes it in.
///   Pure-DH groups (X25519 / P-256 / P-384) are agreed inside the core through
///   ``TLSCryptoCore/TLSKeyExchange``.
/// - Session-ticket validity (`Date`-dependent) and X.509 parsing/trust.
///
/// After ServerHello the core hands its owned transcript + key schedule to a
/// ``TLSClientAuthMachine`` via ``makeAuthMachine(verifyPeer:)`` so the
/// post-ServerHello authentication slice continues with a single transcript owner.
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = TLSFoundationProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no ContinuousClock, no swift-crypto, no X509/ASN.1, typed throws, no key paths.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore

/// The TLS 1.3 client pre-ServerHello FSM over the crypto seam.
public struct TLSClientHandshake<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// Position in the pre-ServerHello flight.
    public enum PreState: Sendable, Equatable {
        /// Before ClientHello has been produced.
        case start
        /// ClientHello sent; waiting for the first ServerHello.
        case waitServerHello
        /// HelloRetryRequest received; waiting for the second ServerHello.
        case waitServerHelloRetry
        /// ServerHello processed; the handshake secret is available and the core
        /// is ready to hand off to ``TLSClientAuthMachine``.
        case serverHelloProcessed
    }

    // MARK: - RFC 8446 §4.1.3 downgrade sentinels

    /// "DOWNGRD" + 0x01 — server negotiated TLS 1.2.
    public static var downgradeSentinelTLS12: [UInt8] {
        [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
    }
    /// "DOWNGRD" + 0x00 — server negotiated TLS 1.1 or below.
    public static var downgradeSentinelTLS11OrBelow: [UInt8] {
        [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]
    }

    /// Whether the given 32-byte ServerHello random ends with a downgrade sentinel.
    public static func hasDowngradeSentinel(_ random: [UInt8]) -> Bool {
        guard random.count >= 8 else { return false }
        let tail = Array(random.suffix(8))
        return tail == downgradeSentinelTLS12 || tail == downgradeSentinelTLS11OrBelow
    }

    // MARK: - Stored Fields (all value types)

    /// The running transcript hash. **Owned by this core.**
    private var transcript: TLSTranscriptHash<C>

    /// The key schedule. For a PSK handshake it is advanced to the early-secret
    /// state during ``produceClientHello``; otherwise it is reinitialised at
    /// ServerHello with the negotiated cipher suite.
    private var keySchedule: TLSKeySchedule<C>

    /// The cipher suite. Provisional (the PSK ticket suite) until ServerHello
    /// resolves the negotiated suite, or until HelloRetryRequest fixes it.
    private var cipherSuite: CipherSuite

    private var state: PreState

    /// Whether a PSK was offered (drives the early-secret ownership and the
    /// "do not reinitialise the key schedule at ServerHello" branch).
    private let pskOffered: Bool

    /// Whether 0-RTT early data is being attempted (cleared on HelloRetryRequest).
    private var attemptingEarlyData: Bool

    /// Whether a HelloRetryRequest has already been processed (only one allowed).
    private var receivedHelloRetryRequest: Bool

    /// Captured outputs of ServerHello processing (read by the adapter).
    public private(set) var clientHandshakeSecret: [UInt8]?
    public private(set) var serverHandshakeSecret: [UInt8]?
    public private(set) var pskAccepted: Bool

    // MARK: - Initialization

    /// Constructs the pre-ServerHello machine.
    ///
    /// - Parameters:
    ///   - cipherSuite: The provisional cipher suite (the PSK ticket suite for a
    ///     resumption attempt, or the suite the adapter intends to use).
    ///   - pskOffered: Whether the client is offering a PSK (resumption).
    public init(cipherSuite: CipherSuite, pskOffered: Bool) {
        self.transcript = TLSTranscriptHash<C>(cipherSuite: cipherSuite)
        self.keySchedule = TLSKeySchedule<C>(cipherSuite: cipherSuite)
        self.cipherSuite = cipherSuite
        self.state = .start
        self.pskOffered = pskOffered
        self.attemptingEarlyData = false
        self.receivedHelloRetryRequest = false
        self.clientHandshakeSecret = nil
        self.serverHandshakeSecret = nil
        self.pskAccepted = false
    }

    // MARK: - Accessors

    /// The current pre-ServerHello state.
    public var currentState: PreState { state }

    /// The negotiated (or provisional) cipher suite.
    public var negotiatedCipherSuite: CipherSuite { cipherSuite }

    /// Whether a HelloRetryRequest was processed.
    public var helloRetryRequestReceived: Bool { receivedHelloRetryRequest }

    // MARK: - ClientHello: PSK binder + transcript

    /// PSK material for a resumption ClientHello: the resumption PSK and whether
    /// the ticket's binder is a resumption binder (always `true` for tickets).
    public struct PSKBinderInput: Sendable {
        public let psk: [UInt8]
        public let isResumption: Bool
        public init(psk: [UInt8], isResumption: Bool) {
            self.psk = psk
            self.isResumption = isResumption
        }
    }

    /// Finalises a ClientHello whose `extensions` already contain everything
    /// EXCEPT the `pre_shared_key` extension (which must be last), computes the PSK
    /// binder when `pskBinder` is present, folds the resulting ClientHello into the
    /// transcript, and derives the 0-RTT early-traffic-secret when requested.
    ///
    /// For a non-PSK ClientHello (`pskBinder == nil` and `offeredPsks == nil`) the
    /// core simply encodes the ClientHello from `extensions`, folds it into the
    /// transcript, and returns its bytes.
    ///
    /// The binder computation matches the legacy two-pass build byte-for-byte: the
    /// early secret is derived from the PSK, the binder key from the early secret,
    /// and the binder is `finishedVerifyData` over the truncated-ClientHello
    /// transcript hash. The truncation length is `OfferedPsks.bindersSize`.
    ///
    /// - Parameters:
    ///   - random: The 32-byte client random.
    ///   - legacySessionID: The legacy session id.
    ///   - cipherSuites: The offered cipher suites (in order).
    ///   - extensions: All extensions EXCEPT `pre_shared_key`.
    ///   - offeredPsks: The PSK offer (identities + placeholder binders), or `nil`.
    ///   - pskBinder: The PSK key material, or `nil` for a non-PSK ClientHello.
    ///   - attemptEarlyData: Whether to derive the 0-RTT early-traffic-secret.
    /// - Returns: The complete ClientHello handshake-message bytes (header included)
    ///   and, when 0-RTT was requested, the derived `client_early_traffic_secret`.
    public mutating func produceClientHello(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension],
        offeredPsks: OfferedPsks?,
        pskBinder: PSKBinderInput?,
        attemptEarlyData: Bool
    ) throws(TLSHandshakeError) -> (clientHello: [UInt8], earlyTrafficSecret: [UInt8]?) {
        guard state == .start else {
            throw .unexpectedMessage("ClientHello already produced")
        }

        // For a PSK handshake the early secret is derived from the PSK before the
        // binder is computed (the binder transcript is over the truncated CH only).
        if let pskBinder {
            keySchedule.deriveEarlySecret(psk: pskBinder.psk)
        }

        let clientHelloMessage = try buildClientHelloBytes(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensions,
            offeredPsks: offeredPsks,
            pskBinder: pskBinder,
            binderTranscriptPrefix: nil
        )

        // Fold the ClientHello into the transcript.
        transcript.update(with: clientHelloMessage.span)

        // Derive the 0-RTT early-traffic-secret over the ClientHello transcript.
        var earlyTrafficSecret: [UInt8]?
        if attemptEarlyData, pskBinder != nil {
            attemptingEarlyData = true
            var earlyTranscript = TLSTranscriptHash<C>(cipherSuite: cipherSuite)
            earlyTranscript.update(with: clientHelloMessage.span)
            do {
                earlyTrafficSecret = try keySchedule.deriveClientEarlyTrafficSecret(
                    transcriptHash: earlyTranscript.currentHash()
                )
            } catch {
                throw .internalError("Failed to derive client early traffic secret")
            }
        }

        state = .waitServerHello
        return (clientHelloMessage, earlyTrafficSecret)
    }

    /// Builds the ClientHello bytes, computing the PSK binder when `pskBinder` is
    /// present. `binderTranscriptPrefix` is the transcript over which the binder is
    /// computed BEFORE the truncated ClientHello is folded in: `nil` for the first
    /// ClientHello (fresh transcript), or the running `message_hash`+HRR transcript
    /// for ClientHello2. Returns a single-assignment `[UInt8]` so the caller can
    /// safely take its `.span`.
    private func buildClientHelloBytes(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension],
        offeredPsks: OfferedPsks?,
        pskBinder: PSKBinderInput?,
        binderTranscriptPrefix: TLSTranscriptHash<C>?
    ) throws(TLSHandshakeError) -> [UInt8] {
        guard let offeredPsks, let pskBinder else {
            return try encodeClientHello(
                random: random,
                legacySessionID: legacySessionID,
                cipherSuites: cipherSuites,
                extensions: extensions
            )
        }

        // First pass: ClientHello with placeholder binders.
        var psk = offeredPsks
        var extensionsWithPsk = extensions
        extensionsWithPsk.append(.preSharedKeyClient(psk))
        let placeholder = try encodeClientHello(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensionsWithPsk
        )

        // Compute the truncated transcript (excluding the binders section).
        let bindersSectionSize = psk.bindersSize
        guard placeholder.count >= bindersSectionSize else {
            throw .internalError("ClientHello shorter than PSK binders section")
        }
        let truncated = Array(placeholder.prefix(placeholder.count - bindersSectionSize))

        var binderTranscript = binderTranscriptPrefix?.copy()
            ?? TLSTranscriptHash<C>(cipherSuite: cipherSuite)
        binderTranscript.update(with: truncated.span)
        let binderHash = binderTranscript.currentHash()

        let binderKey: [UInt8]
        do {
            binderKey = try keySchedule.deriveBinderKey(isResumption: pskBinder.isResumption)
        } catch {
            throw .internalError("Failed to derive PSK binder key")
        }
        let finishedKeyForBinder: [UInt8]
        do {
            finishedKeyForBinder = try keySchedule.finishedKey(from: binderKey)
        } catch {
            throw .internalError("Failed to derive PSK binder finished key")
        }
        let binder = keySchedule.finishedVerifyData(
            forKey: finishedKeyForBinder,
            transcriptHash: binderHash
        )

        // Second pass: ClientHello with the real binder.
        psk.binders = [binder]
        var finalExtensions = extensions
        finalExtensions.append(.preSharedKeyClient(psk))
        return try encodeClientHello(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: finalExtensions
        )
    }

    private func encodeClientHello(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension]
    ) throws(TLSHandshakeError) -> [UInt8] {
        let clientHello: ClientHello
        do {
            clientHello = try ClientHello(
                random: random,
                legacySessionID: legacySessionID,
                cipherSuites: cipherSuites,
                extensions: extensions
            )
            return try clientHello.encodeAsHandshakeBytes()
        } catch {
            throw .internalError("ClientHello encode failed: \(error)")
        }
    }

    // MARK: - HelloRetryRequest: synthetic transcript + ClientHello2

    /// Applies the RFC 8446 §4.4.1 HelloRetryRequest transcript transform: replaces
    /// the running transcript with the `message_hash` synthetic message of
    /// ClientHello1 and folds the HRR into it. The cipher suite is fixed to the
    /// HRR's suite (the second ServerHello must match it).
    ///
    /// 0-RTT is abandoned on HRR (RFC 8446 §4.2.10). Only one HRR is permitted.
    ///
    /// - Parameters:
    ///   - cipherSuite: The HelloRetryRequest cipher suite.
    ///   - rawMessageBytes: The complete HelloRetryRequest handshake message.
    public mutating func applyHelloRetryRequest(
        cipherSuite: CipherSuite,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) {
        guard !receivedHelloRetryRequest else {
            throw .unexpectedMessage("Received second HelloRetryRequest")
        }
        receivedHelloRetryRequest = true
        attemptingEarlyData = false

        self.cipherSuite = cipherSuite

        // Synthetic message_hash(ClientHello1), then HRR.
        let clientHello1Hash = transcript.currentHash()
        transcript = TLSTranscriptHash<C>.fromMessageHash(
            clientHello1Hash: clientHello1Hash,
            cipherSuite: cipherSuite
        )
        transcript.update(with: rawMessageBytes.span)
        state = .waitServerHelloRetry
    }

    /// Finalises a ClientHello2 after a HelloRetryRequest: optionally recomputes the
    /// PSK binder over the *current* transcript (which already contains the
    /// `message_hash` + HRR), folds ClientHello2 into the transcript, and returns
    /// its bytes. The 0-RTT early-traffic-secret is never derived for ClientHello2.
    ///
    /// - Parameters: as ``produceClientHello`` (minus `attemptEarlyData`).
    /// - Returns: The complete ClientHello2 handshake-message bytes.
    public mutating func produceClientHello2(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension],
        offeredPsks: OfferedPsks?,
        pskBinder: PSKBinderInput?
    ) throws(TLSHandshakeError) -> [UInt8] {
        guard state == .waitServerHelloRetry else {
            throw .unexpectedMessage("ClientHello2 produced out of order")
        }

        // The ClientHello2 binder is computed over the running transcript
        // (message_hash + HRR) plus the truncated ClientHello2.
        let clientHelloMessage = try buildClientHelloBytes(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensions,
            offeredPsks: offeredPsks,
            pskBinder: pskBinder,
            binderTranscriptPrefix: transcript
        )

        transcript.update(with: clientHelloMessage.span)
        return clientHelloMessage
    }

    // MARK: - ServerHello

    /// The (EC)DHE input for ServerHello processing. For a pure-DH group the core
    /// performs the key agreement itself through ``TLSCryptoCore/TLSKeyExchange``;
    /// for the X25519MLKEM768 hybrid (KEM, not expressible through the DH seam) the
    /// adapter computes the shared secret and passes it as ``precomputedSecret``.
    public enum KeyExchangeInput: Sendable {
        /// Agree the (EC)DHE secret inside the core for a pure-DH group.
        case agree(group: NamedGroup, privateKeyBytes: [UInt8], peerPublicKeyBytes: [UInt8])
        /// Use the shared secret the adapter already computed (hybrid path).
        case precomputed([UInt8])
    }

    /// Ingests a (non-HRR) ServerHello: validates the downgrade sentinel
    /// (fail-closed), folds the ServerHello into the transcript, reinitialises the
    /// key schedule for the negotiated suite when no PSK was accepted, agrees the
    /// (EC)DHE secret, and derives the handshake-traffic secrets.
    ///
    /// `TLSConfiguration`-dependent validation (cipher-suite-was-offered,
    /// session-id-echo, PSK selection rules) stays adapter-side; this method takes
    /// the already-resolved `pskAccepted` flag, the negotiated `cipherSuite`, and
    /// the `serverHello` for its random + transcript bytes.
    ///
    /// - Parameters:
    ///   - serverRandom: The ServerHello.random (checked for the downgrade sentinel).
    ///   - cipherSuite: The negotiated cipher suite.
    ///   - pskAccepted: Whether the server accepted the offered PSK.
    ///   - keyExchange: The (EC)DHE input (pure-DH agreed in-core, hybrid precomputed).
    ///   - rawMessageBytes: The complete ServerHello handshake message.
    /// - Returns: the derived `{client,server}_handshake_traffic_secret`.
    public mutating func ingestServerHello(
        serverRandom: [UInt8],
        cipherSuite: CipherSuite,
        pskAccepted: Bool,
        keyExchange: KeyExchangeInput,
        rawMessageBytes: [UInt8]
    ) throws(TLSHandshakeError) -> (client: [UInt8], server: [UInt8]) {
        guard state == .waitServerHello || state == .waitServerHelloRetry else {
            throw .unexpectedMessage("Unexpected ServerHello in state \(state)")
        }

        // RFC 8446 §4.1.3: downgrade protection — fail closed.
        if Self.hasDowngradeSentinel(serverRandom) {
            throw .downgradeDetected
        }

        self.cipherSuite = cipherSuite
        self.pskAccepted = pskAccepted

        // Compute the (EC)DHE shared secret.
        let sharedSecret: [UInt8]
        switch keyExchange {
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

        // Fold ServerHello into the transcript.
        transcript.update(with: rawMessageBytes.span)

        // Reinitialise the key schedule for the negotiated suite when no PSK was
        // accepted (a PSK handshake already derived the early secret with the PSK).
        if !pskAccepted {
            keySchedule = TLSKeySchedule<C>(cipherSuite: cipherSuite)
            keySchedule.deriveEarlySecret(psk: nil)
        }

        // Derive the handshake-traffic secrets over CH…SH.
        let transcriptHash = transcript.currentHash()
        let secrets: (client: [UInt8], server: [UInt8])
        do {
            secrets = try keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcriptHash
            )
        } catch {
            throw .internalError("Failed to derive handshake secrets")
        }

        clientHandshakeSecret = secrets.client
        serverHandshakeSecret = secrets.server
        state = .serverHelloProcessed
        return secrets
    }

    // MARK: - Hand-off to the authentication FSM

    /// Hands the owned transcript (CH…SH absorbed) and key schedule (at the
    /// handshake-secret state) to a ``TLSClientAuthMachine`` so the post-ServerHello
    /// authentication slice continues with a single transcript owner.
    ///
    /// - Parameters:
    ///   - verifyPeer: The adapter trust-validation flag (gates the auth FSM's
    ///     fail-closed "cert but no key" branch).
    /// - Returns: the authentication FSM, ready at the EncryptedExtensions boundary.
    public consuming func makeAuthMachine(
        verifyPeer: Bool
    ) throws(TLSHandshakeError) -> TLSClientAuthMachine<C> {
        guard state == .serverHelloProcessed,
              let clientHandshakeSecret,
              let serverHandshakeSecret else {
            throw .internalError("Auth machine requested before ServerHello processed")
        }
        return TLSClientAuthMachine<C>(
            transcript: transcript,
            keySchedule: keySchedule,
            cipherSuite: cipherSuite,
            clientHandshakeSecret: clientHandshakeSecret,
            serverHandshakeSecret: serverHandshakeSecret,
            pskUsed: pskAccepted,
            verifyPeer: verifyPeer,
            attemptingEarlyData: attemptingEarlyData
        )
    }
}
