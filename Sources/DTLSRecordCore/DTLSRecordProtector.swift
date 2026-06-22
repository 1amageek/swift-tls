/// The Embedded-clean generic DTLS 1.2 record protector (RFC 5288 — AES-GCM).
///
/// DTLS 1.2 uses explicit-nonce AEAD construction:
/// ```
/// nonce = fixed_IV (4) || explicit_nonce (8)        // explicit_nonce = epoch(2) || seq(6)
/// AAD   = epoch || seq_num || content_type || version || plaintext_length
/// output = explicit_nonce (8) || ciphertext || tag (16)
/// ```
/// This differs from TLS 1.3 (implicit `iv XOR seq`); the AAD and explicit nonce
/// are constructed by the caller (the adapter builds them from the record header)
/// and passed in as values, so this core holds no sequence/epoch state and no
/// `Mutex` — Embedded-clean.
///
/// `DTLSRecordProtector<C, A>` carries one keyed AEAD `A: AEAD` plus the 4-byte
/// fixed IV, mirroring the proven QUIC ``QUICPacketProtectionCore/PacketProtector``
/// (AEAD + IV value type sealing/opening over the `CryptoProvider.AEAD` seam). The
/// adapter holds one protector per direction (write key / read key).
///
/// AEAD-open failure throws ``DTLSRecordProtectionError/decryptionFailed`` — no
/// silent fallback, never a garbage/empty plaintext.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto

public struct DTLSRecordProtector<C: CryptoProvider, A: AEAD>: Sendable {
    /// The keyed AEAD for this direction.
    public let aead: A

    /// The 4-byte fixed IV (from the DTLS key block).
    public let fixedIV: [UInt8]

    /// The fixed-IV length for DTLS 1.2 AES-GCM (RFC 5288).
    public static var fixedIVLength: Int { 4 }

    /// The explicit-nonce length (epoch(2) || seq(6)).
    public static var explicitNonceLength: Int { 8 }

    /// The AEAD authentication tag length (16 bytes).
    public static var tagLength: Int { A.tagLength }

    /// Creates a protector from a keyed AEAD and the 4-byte fixed IV.
    ///
    /// - Throws: ``DTLSRecordProtectionError/invalidFixedIVLength(expected:actual:)``
    ///   if `fixedIV` is not 4 bytes.
    public init(
        aead: A,
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) {
        guard fixedIV.count == Self.fixedIVLength else {
            throw .invalidFixedIVLength(expected: Self.fixedIVLength, actual: fixedIV.count)
        }
        self.aead = aead
        self.fixedIV = fixedIV
    }

    // MARK: - Seal (encrypt)

    /// Seals `plaintext` for the given `explicitNonce` (8 bytes) and `aad`.
    ///
    /// - Returns: `explicit_nonce (8) || ciphertext || tag (16)`.
    public func seal(
        plaintext: [UInt8],
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        guard explicitNonce.count == Self.explicitNonceLength else {
            throw .invalidExplicitNonceLength(
                expected: Self.explicitNonceLength, actual: explicitNonce.count)
        }

        // nonce = fixed_IV (4) || explicit_nonce (8) = 12 bytes
        var nonce = fixedIV
        nonce.append(contentsOf: explicitNonce)

        let sealed: [UInt8]
        do {
            sealed = try aead.seal(plaintext.span, nonce: nonce.span, aad: aad.span)
        } catch {
            throw .crypto(error)
        }

        // Output: explicit_nonce || ciphertext || tag
        var output = explicitNonce
        output.append(contentsOf: sealed)
        return output
    }

    // MARK: - Open (decrypt)

    /// Opens a DTLS ciphertext (`explicit_nonce (8) || ciphertext || tag (16)`)
    /// for the given `aad`, recovering the plaintext.
    ///
    /// Throws ``DTLSRecordProtectionError/decryptionFailed(_:)`` on any AEAD-open
    /// failure — no silent fallback, never a garbage plaintext.
    public func open(
        ciphertext: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        // Minimum: 8 (explicit nonce) + 0 (data) + 16 (tag) = 24 bytes.
        let minimum = Self.explicitNonceLength + Self.tagLength
        guard ciphertext.count >= minimum else {
            throw .ciphertextTooShort(minimum: minimum, actual: ciphertext.count)
        }

        let explicitNonce = Array(ciphertext[0..<Self.explicitNonceLength])
        let encryptedWithTag = Array(ciphertext[Self.explicitNonceLength...])

        // nonce = fixed_IV (4) || explicit_nonce (8)
        var nonce = fixedIV
        nonce.append(contentsOf: explicitNonce)

        do {
            return try aead.open(encryptedWithTag.span, nonce: nonce.span, aad: aad.span)
        } catch {
            // Uniform decrypt-failure surface (no leak of the failure reason).
            throw .decryptionFailed
        }
    }
}
