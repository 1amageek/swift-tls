/// TLS 1.3 Key Schedule (RFC 8446 §7.1), Embedded-clean.
///
/// Derives the Early / Handshake / Master secret hierarchy and all traffic,
/// finished, exporter, resumption, and binder secrets through the
/// ``P2PCoreCrypto/CryptoProvider`` seam (HKDF + hash + HMAC) instead of
/// swift-crypto. Secrets are raw `[UInt8]` (not `SymmetricKey`).
///
/// ```
///             0
///             |
///   PSK ->  HKDF-Extract = Early Secret
///             |
///       Derive-Secret(., "derived", "")
///             |
///  (EC)DHE -> HKDF-Extract = Handshake Secret
///             |
///       Derive-Secret(., "derived", "")
///             |
///     0 -> HKDF-Extract = Master Secret
/// ```
///
/// The state machine (`initial → earlySecret → handshakeSecret → masterSecret`)
/// enforces RFC ordering; out-of-order use throws
/// ``TLSKeyScheduleCoreError/invalidState`` (no silent fallback).
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = TLSCryptoProvider`. Embedded-clean: no Foundation, no `any`, no
/// Mutex, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore

/// The TLS 1.3 key schedule over the crypto seam.
public struct TLSKeySchedule<C: CryptoProvider>: Sendable {

    /// Position in the Early → Handshake → Master secret chain.
    private enum KeyScheduleState: Sendable {
        case initial
        case earlySecret([UInt8])
        case handshakeSecret([UInt8])
        case masterSecret([UInt8])
    }

    private var state: KeyScheduleState

    /// The negotiated cipher suite (selects the hash + HKDF).
    public let cipherSuite: CipherSuite

    /// Hash length in bytes (32 for SHA-256, 48 for SHA-384).
    public let hashLength: Int

    // MARK: - Initialization

    /// Creates a fresh key schedule in the `initial` state.
    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        self.state = .initial
        self.cipherSuite = cipherSuite
        self.hashLength = cipherSuite.hashLength
    }

    // MARK: - Early Secret

    /// `early_secret = HKDF-Extract(salt=0^Hash.length, IKM = PSK || 0^Hash.length)`.
    public mutating func deriveEarlySecret(psk: [UInt8]? = nil) {
        let ikm = psk ?? [UInt8](repeating: 0, count: hashLength)
        let salt = [UInt8](repeating: 0, count: hashLength)
        let earlySecret = TLSHkdf<C>.extract(salt: salt.span, ikm: ikm.span, cipherSuite: cipherSuite)
        state = .earlySecret(earlySecret)
    }

    // MARK: - Handshake Secret

    /// Derives `{client,server}_handshake_traffic_secret` from the (EC)DHE shared
    /// secret and the ClientHello…ServerHello transcript hash.
    public mutating func deriveHandshakeSecrets(
        sharedSecret: [UInt8],
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> (client: [UInt8], server: [UInt8]) {
        switch state {
        case .initial:
            deriveEarlySecret(psk: nil)
        case .earlySecret:
            break
        case .handshakeSecret, .masterSecret:
            throw .invalidState
        }

        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState
        }

        // Derive-Secret(early_secret, "derived", "")
        let empty = TLSHkdf<C>.emptyTranscriptHash(cipherSuite: cipherSuite)
        let derivedSecret = try TLSHkdf<C>.deriveSecret(
            secret: earlySecret.span,
            label: "derived",
            transcriptHash: empty.span,
            cipherSuite: cipherSuite
        )

        // HKDF-Extract(derived_secret, shared_secret)
        let handshakeSecret = TLSHkdf<C>.extract(
            salt: derivedSecret.span,
            ikm: sharedSecret.span,
            cipherSuite: cipherSuite
        )
        state = .handshakeSecret(handshakeSecret)

        let clientSecret = try TLSHkdf<C>.deriveSecret(
            secret: handshakeSecret.span,
            label: "c hs traffic",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
        let serverSecret = try TLSHkdf<C>.deriveSecret(
            secret: handshakeSecret.span,
            label: "s hs traffic",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
        return (client: clientSecret, server: serverSecret)
    }

    // MARK: - Application Secret

    /// Derives `{client,server}_application_traffic_secret_0` from the
    /// ClientHello…server Finished transcript hash.
    public mutating func deriveApplicationSecrets(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> (client: [UInt8], server: [UInt8]) {
        guard case .handshakeSecret(let handshakeSecret) = state else {
            throw .invalidState
        }

        // Derive-Secret(handshake_secret, "derived", "")
        let empty = TLSHkdf<C>.emptyTranscriptHash(cipherSuite: cipherSuite)
        let derivedSecret = try TLSHkdf<C>.deriveSecret(
            secret: handshakeSecret.span,
            label: "derived",
            transcriptHash: empty.span,
            cipherSuite: cipherSuite
        )

        // HKDF-Extract(derived_secret, 0)
        let zeroIkm = [UInt8](repeating: 0, count: hashLength)
        let masterSecret = TLSHkdf<C>.extract(
            salt: derivedSecret.span,
            ikm: zeroIkm.span,
            cipherSuite: cipherSuite
        )
        state = .masterSecret(masterSecret)

        let clientSecret = try TLSHkdf<C>.deriveSecret(
            secret: masterSecret.span,
            label: "c ap traffic",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
        let serverSecret = try TLSHkdf<C>.deriveSecret(
            secret: masterSecret.span,
            label: "s ap traffic",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
        return (client: clientSecret, server: serverSecret)
    }

    // MARK: - Key Update

    /// `application_traffic_secret_N+1 =
    ///   HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)`.
    public func nextApplicationSecret(
        from currentSecret: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        let empty = [UInt8]()
        return try TLSHkdf<C>.expandLabel(
            secret: currentSecret.span,
            label: "traffic upd",
            context: empty.span,
            length: hashLength,
            cipherSuite: cipherSuite
        )
    }

    // MARK: - Finished Key

    /// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)`.
    public func finishedKey(from baseKey: [UInt8]) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        let empty = [UInt8]()
        return try TLSHkdf<C>.expandLabel(
            secret: baseKey.span,
            label: "finished",
            context: empty.span,
            length: hashLength,
            cipherSuite: cipherSuite
        )
    }

    /// `verify_data = HMAC(finished_key, Transcript-Hash)` for the suite's hash.
    public func finishedVerifyData(
        forKey key: [UInt8],
        transcriptHash: [UInt8]
    ) -> [UInt8] {
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            return C.HMACSHA384.authenticationCode(for: transcriptHash.span, key: key.span)
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            return C.HMACSHA256.authenticationCode(for: transcriptHash.span, key: key.span)
        }
    }

    // MARK: - Exporter Master Secret

    /// `exporter_master_secret = Derive-Secret(master_secret, "exp master", CH...SF)`.
    public func deriveExporterMasterSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        guard case .masterSecret(let masterSecret) = state else {
            throw .invalidState
        }
        return try TLSHkdf<C>.deriveSecret(
            secret: masterSecret.span,
            label: "exp master",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
    }

    // MARK: - Resumption Master Secret

    /// `resumption_master_secret = Derive-Secret(master_secret, "res master", CH...CF)`.
    public func deriveResumptionMasterSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        guard case .masterSecret(let masterSecret) = state else {
            throw .invalidState
        }
        return try TLSHkdf<C>.deriveSecret(
            secret: masterSecret.span,
            label: "res master",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
    }

    /// `PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
    /// ticket_nonce, Hash.length)` (RFC 8446 §4.6.1).
    public func deriveResumptionPSK(
        resumptionMasterSecret: [UInt8],
        ticketNonce: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        try TLSHkdf<C>.expandLabel(
            secret: resumptionMasterSecret.span,
            label: "resumption",
            context: ticketNonce.span,
            length: hashLength,
            cipherSuite: cipherSuite
        )
    }

    // MARK: - PSK / Early Secrets

    /// `binder_key = Derive-Secret(early_secret, "res binder"|"ext binder", "")`.
    public func deriveBinderKey(isResumption: Bool) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState
        }
        let label = isResumption ? "res binder" : "ext binder"
        let empty = TLSHkdf<C>.emptyTranscriptHash(cipherSuite: cipherSuite)
        return try TLSHkdf<C>.deriveSecret(
            secret: earlySecret.span,
            label: label,
            transcriptHash: empty.span,
            cipherSuite: cipherSuite
        )
    }

    /// `client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)`.
    public func deriveClientEarlyTrafficSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState
        }
        return try TLSHkdf<C>.deriveSecret(
            secret: earlySecret.span,
            label: "c e traffic",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
    }

    /// `early_exporter_master_secret = Derive-Secret(early_secret, "e exp master", ClientHello)`.
    public func deriveEarlyExporterMasterSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState
        }
        return try TLSHkdf<C>.deriveSecret(
            secret: earlySecret.span,
            label: "e exp master",
            transcriptHash: transcriptHash.span,
            cipherSuite: cipherSuite
        )
    }

    /// The current early secret (for PSK-related computations).
    public func currentEarlySecret() throws(TLSKeyScheduleCoreError) -> [UInt8] {
        guard case .earlySecret(let earlySecret) = state else {
            throw .invalidState
        }
        return earlySecret
    }

    // MARK: - Exporter Keying Material

    /// Exported keying material (RFC 8446 §7.5), a two-step derivation:
    /// `Derive-Secret(exporter_master_secret, label, "")` then
    /// `HKDF-Expand-Label(., "exporter", Hash(context), length)`.
    public func exportKeyingMaterial(
        exporterMasterSecret: [UInt8],
        label: String,
        context: [UInt8]?,
        length: Int
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        let emptyHash = TLSHkdf<C>.emptyTranscriptHash(cipherSuite: cipherSuite)
        let derivedSecret = try TLSHkdf<C>.expandLabel(
            secret: exporterMasterSecret.span,
            label: label,
            context: emptyHash.span,
            length: hashLength,
            cipherSuite: cipherSuite
        )

        var contextHash = emptyHash
        if let context {
            contextHash = TLSHkdf<C>.hash(context.span, cipherSuite: cipherSuite)
        }
        return try TLSHkdf<C>.expandLabel(
            secret: derivedSecret.span,
            label: "exporter",
            context: contextHash.span,
            length: length,
            cipherSuite: cipherSuite
        )
    }
}
