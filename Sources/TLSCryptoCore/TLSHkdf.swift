/// TLS 1.3 HKDF primitives (RFC 8446 §7.1), Embedded-clean.
///
/// Implements `HKDF-Extract`, `HKDF-Expand-Label`, and `Derive-Secret` over the
/// ``P2PCoreCrypto/KeyDerivation`` and ``P2PCoreCrypto/HashFunction`` seams. The
/// cipher suite selects SHA-256 (`C.HKDFSHA256`/`C.SHA256`) or SHA-384
/// (`C.HKDFSHA384`/`C.SHA384`); the branch is a closed switch on ``CipherSuite``,
/// mirroring the byte-for-byte behavior of the adapter's swift-crypto path.
///
/// All secrets are raw `[UInt8]` (not `SymmetricKey`). The `HkdfLabel` structure
/// (`uint16 length || opaque label<7..255> || opaque context<0..255>`) is built
/// with a `ByteWriter` exactly as the proven QUIC core does.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore

/// TLS 1.3 HKDF helpers parameterised by the crypto provider seam.
public enum TLSHkdf<C: CryptoProvider> {

    // MARK: - HKDF-Extract

    /// `HKDF-Extract(salt, ikm)` for the suite's hash.
    public static func extract(
        salt: Span<UInt8>,
        ikm: Span<UInt8>,
        cipherSuite: CipherSuite
    ) -> [UInt8] {
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            return C.HKDFSHA384().extract(salt: salt, ikm: ikm)
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            return C.HKDFSHA256().extract(salt: salt, ikm: ikm)
        }
    }

    // MARK: - HKDF-Expand-Label

    /// `HKDF-Expand-Label(secret, label, context, length)` with the `"tls13 "`
    /// label prefix (RFC 8446 §7.1).
    public static func expandLabel(
        secret: Span<UInt8>,
        label: String,
        context: Span<UInt8>,
        length: Int,
        cipherSuite: CipherSuite
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        let prefixedLabel = Array("tls13 \(label)".utf8)
        var writer = ByteWriter()
        writer.writeUInt16(UInt16(truncatingIfNeeded: length))
        writer.writeUInt8(UInt8(truncatingIfNeeded: prefixedLabel.count))
        writer.writeBytes(prefixedLabel)
        writer.writeUInt8(UInt8(truncatingIfNeeded: context.count))
        // ByteWriter.writeBytes(Span) is not part of the seam surface; copy the
        // context once into the label structure.
        writer.writeBytes(spanToArray(context))
        let info = writer.finishArray()

        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            do {
                return try C.HKDFSHA384().expand(prk: secret, info: info.span, length: length)
            } catch {
                throw .crypto(error)
            }
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            do {
                return try C.HKDFSHA256().expand(prk: secret, info: info.span, length: length)
            } catch {
                throw .crypto(error)
            }
        }
    }

    // MARK: - Derive-Secret

    /// `Derive-Secret(secret, label, messages) =
    ///   HKDF-Expand-Label(secret, label, Transcript-Hash(messages), Hash.length)`.
    ///
    /// The caller passes the already-computed transcript hash as `transcriptHash`.
    public static func deriveSecret(
        secret: Span<UInt8>,
        label: String,
        transcriptHash: Span<UInt8>,
        cipherSuite: CipherSuite
    ) throws(TLSKeyScheduleCoreError) -> [UInt8] {
        try expandLabel(
            secret: secret,
            label: label,
            context: transcriptHash,
            length: cipherSuite.hashLength,
            cipherSuite: cipherSuite
        )
    }

    // MARK: - Hash of empty / arbitrary input

    /// `Transcript-Hash("")` — the hash of the empty string for the suite's hash.
    public static func emptyTranscriptHash(cipherSuite: CipherSuite) -> [UInt8] {
        let empty = [UInt8]()
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            return C.SHA384.hash(empty.span)
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            return C.SHA256.hash(empty.span)
        }
    }

    /// Hash of an arbitrary buffer for the suite's hash.
    public static func hash(_ data: Span<UInt8>, cipherSuite: CipherSuite) -> [UInt8] {
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            return C.SHA384.hash(data)
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            return C.SHA256.hash(data)
        }
    }

    // MARK: - Span helper

    /// Copies a `Span<UInt8>` into a fresh `[UInt8]` (Embedded-clean, no
    /// Foundation). Used where a contiguous owned buffer is required.
    @inline(__always)
    static func spanToArray(_ span: Span<UInt8>) -> [UInt8] {
        var array = [UInt8]()
        array.reserveCapacity(span.count)
        for index in 0..<span.count { array.append(span[index]) }
        return array
    }
}
