/// The closed cipher-suite enum that lets one value type carry the record-layer
/// AEAD for any TLS 1.3 suite WITHOUT an `any AEAD` existential.
///
/// TLS 1.3 mandates three AEAD suites (RFC 8446 §B.4): `AEAD_AES_128_GCM`,
/// `AEAD_AES_256_GCM`, and `AEAD_CHACHA20_POLY1305`. Each provider exposes them as
/// three DISTINCT `associatedtype`s (`C.AESGCM128` / `C.AESGCM256` / `C.ChaChaPoly`),
/// so a single `TLSRecordProtector<C, A>` cannot cover all three at compile time.
/// `TLSRecordSuiteProtector<C>` is a closed `enum` over the generic
/// ``TLSRecordCore/TLSRecordProtector`` specialised at each provider AEAD — the
/// exact analogue of the proven QUIC ``SuiteProtector``. A generic upper layer
/// (`<C: CryptoProvider>`) specialises cleanly under Embedded Swift; the facade
/// instantiates it at `C = TLSCryptoProvider`.
///
/// Sequence numbers are NOT held here (the protector core is sequence-stateless);
/// the engine that owns this value advances the counter under its own (caller's)
/// lock — Embedded-clean, no `Mutex`.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSRecordCore

/// A cipher-suite-tagged single-direction record protector. Carries the generic
/// ``TLSRecordCore/TLSRecordProtector`` for the selected AEAD; provides the uniform
/// protect/unprotect surface the engine needs without `any`.
public enum TLSRecordSuiteProtector<C: CryptoProvider>: Sendable {
    case aes128GCM(TLSRecordProtector<C, C.AESGCM128>)
    case aes256GCM(TLSRecordProtector<C, C.AESGCM256>)
    case chaCha20Poly1305(TLSRecordProtector<C, C.ChaChaPoly>)

    // MARK: - Construction (RFC 8446 §7.3 key material)

    /// Builds a single-direction protector from the derived key + IV bytes for
    /// `cipherSuite`. The AEAD is constructed through the `CryptoProvider` seam
    /// factories (`C.makeAESGCM128` / `C.makeAESGCM256` / `C.makeChaChaPoly`).
    public static func make(
        cipherSuite: CipherSuite,
        key: [UInt8],
        iv: [UInt8]
    ) throws(TLSRecordProtectionError) -> TLSRecordSuiteProtector<C> {
        switch cipherSuite {
        case .tls_aes_128_gcm_sha256:
            let aead: C.AESGCM128
            do { aead = try C.makeAESGCM128(key: key.span) } catch { throw .crypto(error) }
            return .aes128GCM(try TLSRecordProtector<C, C.AESGCM128>(aead: aead, iv: iv))
        case .tls_aes_256_gcm_sha384:
            let aead: C.AESGCM256
            do { aead = try C.makeAESGCM256(key: key.span) } catch { throw .crypto(error) }
            return .aes256GCM(try TLSRecordProtector<C, C.AESGCM256>(aead: aead, iv: iv))
        case .tls_chacha20_poly1305_sha256:
            let aead: C.ChaChaPoly
            do { aead = try C.makeChaChaPoly(key: key.span) } catch { throw .crypto(error) }
            return .chaCha20Poly1305(try TLSRecordProtector<C, C.ChaChaPoly>(aead: aead, iv: iv))
        }
    }

    /// Builds the protector from a raw traffic `secret` (derives key + IV).
    public static func fromSecret(
        cipherSuite: CipherSuite,
        secret: [UInt8]
    ) throws(TLSRecordProtectionError) -> TLSRecordSuiteProtector<C> {
        let keys: TLSTrafficKeys
        do {
            keys = try TLSTrafficKeys.derive(secret: secret.span, cipherSuite: cipherSuite, provider: C.self)
        } catch {
            throw .invalidInnerPlaintext
        }
        return try make(cipherSuite: cipherSuite, key: keys.key, iv: keys.iv)
    }

    // MARK: - Uniform protection surface (dispatch without `any`)

    /// Seals `content` of `type` at `sequenceNumber`, returning `ciphertext || tag`.
    public func protect(
        content: [UInt8],
        type: TLSContentType,
        sequenceNumber: UInt64
    ) throws(TLSRecordProtectionError) -> [UInt8] {
        switch self {
        case .aes128GCM(let p):        return try p.protect(content: content, type: type, sequenceNumber: sequenceNumber)
        case .aes256GCM(let p):        return try p.protect(content: content, type: type, sequenceNumber: sequenceNumber)
        case .chaCha20Poly1305(let p): return try p.protect(content: content, type: type, sequenceNumber: sequenceNumber)
        }
    }

    /// Opens a ciphertext record body at `sequenceNumber`, recovering
    /// `(content, content_type)`. Throws on tag mismatch — no silent fallback.
    public func unprotect(
        ciphertext: [UInt8],
        sequenceNumber: UInt64
    ) throws(TLSRecordProtectionError) -> (content: [UInt8], type: TLSContentType) {
        switch self {
        case .aes128GCM(let p):        return try p.unprotect(ciphertext: ciphertext, sequenceNumber: sequenceNumber)
        case .aes256GCM(let p):        return try p.unprotect(ciphertext: ciphertext, sequenceNumber: sequenceNumber)
        case .chaCha20Poly1305(let p): return try p.unprotect(ciphertext: ciphertext, sequenceNumber: sequenceNumber)
        }
    }
}
