/// The closed cipher-suite enum that lets one value type carry the DTLS 1.2
/// record-layer AEAD for any negotiated suite WITHOUT an `any AEAD` existential.
///
/// DTLS 1.2 here uses the ECDHE_ECDSA AEAD suites WebRTC/libp2p mandate
/// (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` / `..._AES_256_GCM_SHA384`). Each
/// provider exposes AES-GCM-128 and AES-GCM-256 as DISTINCT `associatedtype`s
/// (`C.AESGCM128` / `C.AESGCM256`), so a single `DTLSRecordProtector<C, A>` cannot
/// cover both at compile time. `DTLSRecordSuiteProtector<C>` is a closed `enum`
/// over the generic ``DTLSRecordCore/DTLSRecordProtector`` specialised at each
/// provider AEAD — the exact analogue of ``TLSEngineCore/TLSRecordSuiteProtector``.
///
/// Epoch + sequence numbers are NOT held here (the protector core is stateless on
/// the explicit nonce / AAD, which the engine builds per record); the engine that
/// owns this value advances the epoch/seq under its own (caller's) lock —
/// Embedded-clean, no `Mutex`.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import DTLSWireCore
import DTLSRecordCore

/// A cipher-suite-tagged single-direction DTLS record protector. Carries the
/// generic ``DTLSRecordCore/DTLSRecordProtector`` for the selected AEAD; provides
/// the uniform seal/open surface the engine needs without `any`.
public enum DTLSRecordSuiteProtector<C: CryptoProvider>: Sendable {
    case aes128GCM(DTLSRecordProtector<C, C.AESGCM128>)
    case aes256GCM(DTLSRecordProtector<C, C.AESGCM256>)

    // MARK: - Construction (RFC 5288 key + 4-byte fixed IV from the key block)

    /// Builds a single-direction protector from the key + fixed-IV bytes for
    /// `cipherSuite`. The AEAD is constructed through the `CryptoProvider` seam
    /// factories (`C.makeAESGCM128` / `C.makeAESGCM256`).
    public static func make(
        cipherSuite: DTLSCipherSuite,
        key: [UInt8],
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) -> DTLSRecordSuiteProtector<C> {
        switch cipherSuite {
        case .ecdheEcdsaWithAes128GcmSha256, .ecdheRsaWithAes128GcmSha256:
            let aead: C.AESGCM128
            do { aead = try C.makeAESGCM128(key: key.span) } catch { throw .crypto(error) }
            return .aes128GCM(try DTLSRecordProtector<C, C.AESGCM128>(aead: aead, fixedIV: fixedIV))
        case .ecdheEcdsaWithAes256GcmSha384:
            let aead: C.AESGCM256
            do { aead = try C.makeAESGCM256(key: key.span) } catch { throw .crypto(error) }
            return .aes256GCM(try DTLSRecordProtector<C, C.AESGCM256>(aead: aead, fixedIV: fixedIV))
        }
    }

    // MARK: - Uniform protection surface (dispatch without `any`)

    /// Seals `plaintext` for `explicitNonce` (8 bytes: epoch||seq) and `aad`,
    /// returning `explicit_nonce || ciphertext || tag`.
    public func seal(
        plaintext: [UInt8],
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        switch self {
        case .aes128GCM(let p): return try p.seal(plaintext: plaintext, explicitNonce: explicitNonce, aad: aad)
        case .aes256GCM(let p): return try p.seal(plaintext: plaintext, explicitNonce: explicitNonce, aad: aad)
        }
    }

    /// Opens a DTLS ciphertext (`explicit_nonce || ciphertext || tag`) for `aad`,
    /// recovering the plaintext. Throws on tag mismatch — no silent fallback.
    public func open(
        ciphertext: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        switch self {
        case .aes128GCM(let p): return try p.open(ciphertext: ciphertext, aad: aad)
        case .aes256GCM(let p): return try p.open(ciphertext: ciphertext, aad: aad)
        }
    }
}
