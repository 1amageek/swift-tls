/// The Embedded-clean generic TLS 1.3 record protector (RFC 8446 §5.2).
///
/// `TLSRecordProtector<C, A>` is a single-direction protector: it carries one
/// keyed AEAD (`A: AEAD`) plus the 12-byte direction IV, and performs:
/// - `protect`: build inner plaintext (content || content_type), AEAD-seal with
///   nonce = `iv XOR seq`, AAD = the ciphertext record header,
/// - `unprotect`: AEAD-open with nonce = `iv XOR seq`, then strip the inner
///   plaintext padding to recover (content, content_type).
///
/// One protector per direction mirrors the proven QUIC
/// ``QUICPacketProtectionCore/PacketProtector`` shape (a `Sendable` value type
/// holding the AEAD + IV, sealing/opening over the `CryptoProvider.AEAD` seam) and
/// preserves the legacy record cryptor's ability to have send-only or
/// receive-only keys active independently. The cipher suite is selected one level
/// up by the adapter, which builds the concrete `A` from the negotiated suite.
///
/// **Sequence-number state is NOT held here.** The caller passes the record
/// sequence number in as a value and is responsible for advancing it under its
/// own lock (the adapter `TLSRecordCryptor` keeps the `Mutex`-backed counter).
/// This keeps the core free of `Mutex`/Foundation and Embedded-clean.
///
/// AEAD-open failure throws ``TLSRecordProtectionError/badRecordMac`` (every
/// underlying ``P2PCoreCrypto/CryptoError`` collapses to it) — no silent
/// fallback, never a garbage/empty plaintext (RFC 8446 §5.2 padding-oracle
/// prevention).
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore

public struct TLSRecordProtector<C: CryptoProvider, A: AEAD>: Sendable {
    /// The keyed AEAD for this direction.
    public let aead: A

    /// The 12-byte direction IV (RFC 8446 §7.3, "iv").
    public let iv: [UInt8]

    /// The required IV length for TLS 1.3 record AEAD (RFC 8446 §5.3).
    public static var ivLength: Int { 12 }

    /// The AEAD authentication tag length (16 bytes for all TLS 1.3 suites).
    public static var tagLength: Int { A.tagLength }

    /// Maximum TLS 1.3 plaintext fragment size (RFC 8446 §5.1).
    public static var maxPlaintextSize: Int { 16384 }

    /// Creates a single-direction protector from a keyed AEAD and IV.
    ///
    /// - Throws: ``TLSRecordProtectionError/invalidIVLength(expected:actual:)`` if
    ///   `iv` is not 12 bytes.
    public init(
        aead: A,
        iv: [UInt8]
    ) throws(TLSRecordProtectionError) {
        guard iv.count == Self.ivLength else {
            throw .invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        self.aead = aead
        self.iv = iv
    }

    // MARK: - Nonce (RFC 8446 §5.3)

    /// Constructs the per-record nonce: `iv XOR left-padded(sequence_number)`.
    ///
    /// The 64-bit sequence number is XORed (big-endian) into the low 8 bytes of
    /// the 12-byte IV. Precondition (enforced at init): `iv.count == 12`.
    @inline(__always)
    func nonce(sequenceNumber: UInt64) -> [UInt8] {
        var nonce = iv
        let offset = nonce.count - 8
        nonce[offset + 0] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 56)
        nonce[offset + 1] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 48)
        nonce[offset + 2] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 40)
        nonce[offset + 3] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 32)
        nonce[offset + 4] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 24)
        nonce[offset + 5] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 16)
        nonce[offset + 6] ^= UInt8(truncatingIfNeeded: sequenceNumber >> 8)
        nonce[offset + 7] ^= UInt8(truncatingIfNeeded: sequenceNumber)
        return nonce
    }

    // MARK: - AAD (RFC 8446 §5.2)

    /// Builds the AEAD AAD: the TLS ciphertext record header
    /// `0x17 || 0x0303 || uint16(ciphertext_length)`.
    @inline(__always)
    static func aad(ciphertextLength: Int) -> [UInt8] {
        [
            TLSContentType.applicationData.rawValue, // 0x17
            0x03, // legacy version high
            0x03, // legacy version low
            UInt8(truncatingIfNeeded: ciphertextLength >> 8),
            UInt8(truncatingIfNeeded: ciphertextLength),
        ]
    }

    // MARK: - Protect (encrypt)

    /// Seals `content` of `type` into a TLS ciphertext record body
    /// (inner plaintext + AEAD tag), at the given record `sequenceNumber`.
    ///
    /// The caller owns the sequence number: it passes the current value and must
    /// advance its own counter only after this returns successfully.
    ///
    /// - Returns: `ciphertext || tag`.
    public func protect(
        content: [UInt8],
        type: TLSContentType,
        sequenceNumber: UInt64
    ) throws(TLSRecordProtectionError) -> [UInt8] {
        guard content.count <= Self.maxPlaintextSize else {
            throw .plaintextTooLarge(content.count)
        }
        guard sequenceNumber < UInt64.max else {
            throw .sequenceNumberOverflow
        }

        // Inner plaintext = content || content_type (no padding, matching legacy).
        var innerPlaintext = content
        innerPlaintext.append(type.rawValue)

        let ciphertextLength = innerPlaintext.count + Self.tagLength
        let nonceBytes = nonce(sequenceNumber: sequenceNumber)
        let aadBytes = Self.aad(ciphertextLength: ciphertextLength)

        do {
            return try aead.seal(
                innerPlaintext.span,
                nonce: nonceBytes.span,
                aad: aadBytes.span
            )
        } catch {
            throw .crypto(error)
        }
    }

    // MARK: - Unprotect (decrypt)

    /// Opens a TLS ciphertext record body and recovers `(content, content_type)`,
    /// at the given record `sequenceNumber`.
    ///
    /// The caller owns the sequence number: it passes the current value and must
    /// advance its own counter only after this returns successfully.
    ///
    /// Throws ``TLSRecordProtectionError/badRecordMac`` on any AEAD-open failure
    /// (uniform, RFC 8446 §5.2) — no silent fallback, never a garbage plaintext.
    public func unprotect(
        ciphertext: [UInt8],
        sequenceNumber: UInt64
    ) throws(TLSRecordProtectionError) -> (content: [UInt8], type: TLSContentType) {
        guard ciphertext.count >= Self.tagLength else {
            throw .ciphertextTooShort(minimum: Self.tagLength, actual: ciphertext.count)
        }
        guard sequenceNumber < UInt64.max else {
            throw .sequenceNumberOverflow
        }

        let nonceBytes = nonce(sequenceNumber: sequenceNumber)
        let aadBytes = Self.aad(ciphertextLength: ciphertext.count)

        let innerPlaintext: [UInt8]
        do {
            innerPlaintext = try aead.open(
                ciphertext.span,
                nonce: nonceBytes.span,
                aad: aadBytes.span
            )
        } catch {
            // Collapse every AEAD-open failure to a single uniform error
            // (padding-oracle prevention, RFC 8446 §5.2).
            throw .badRecordMac
        }

        guard let parsed = Self.parseInnerPlaintext(innerPlaintext) else {
            throw .invalidInnerPlaintext
        }
        return parsed
    }

    // MARK: - Inner plaintext parsing (RFC 8446 §5.2)

    /// Strips trailing zero padding and recovers the real content type from the
    /// last non-zero byte. Inner plaintext = content || content_type || zeros.
    @inline(__always)
    static func parseInnerPlaintext(
        _ data: [UInt8]
    ) -> (content: [UInt8], type: TLSContentType)? {
        guard !data.isEmpty else { return nil }

        var index = data.count - 1
        while index >= 0 && data[index] == 0 {
            index -= 1
        }
        guard index >= 0 else { return nil }
        guard let contentType = TLSContentType(rawValue: data[index]) else { return nil }

        let content = Array(data[0..<index])
        return (content, contentType)
    }
}
