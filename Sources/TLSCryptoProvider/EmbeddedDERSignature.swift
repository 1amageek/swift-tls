/// Embedded DER-encoded ECDSA signature schemes for the TLS 1.3 CertificateVerify
/// wire (RFC 8446 §4.2.3) — the Embedded-Swift counterpart of the host
/// ``TLSDERP256Signature`` / ``TLSDERP384Signature``.
///
/// The shared Embedded crypto backend (``P2PCrypto/DefaultCryptoProvider`` =
/// `BoringSSLCryptoProvider`) emits ECDSA signatures in *raw* `r || s` p1363 form
/// (64 B for P-256, 96 B for P-384) — correct for Noise / libp2p, but NOT for the
/// TLS 1.3 CertificateVerify wire, which mandates the DER `SEQUENCE { INTEGER r,
/// INTEGER s }` encoding. These wrappers sit over the Boring schemes and convert:
///
/// - `sign`   — Boring signs (raw `r || s`); we split into the fixed-width `r` and
///   `s` halves and DER-encode them via `P2PCoreDER.DERWriter`, which applies the
///   ASN.1 INTEGER minimal/sign-bit rules (strip leading `0x00`, prepend `0x00`
///   when the high bit is set). The DER output is BYTE-IDENTICAL to the host
///   ``TLSDERP256Signature`` / CryptoKit `derRepresentation` for the same `r || s`.
/// - `isValid` — DER-decode the wire signature back to `r` and `s` (re-padded to
///   the fixed scalar width), reassemble raw `r || s`, and verify via Boring.
///
/// FAIL-CLOSED: a malformed DER signature, a wrong-length key, or a wrong-length
/// `r || s` from the backend is an explicit `false` from `isValid` / a typed throw
/// from `sign` — never a silent accept or a fabricated signature.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto; generic only over the
/// concrete Boring scheme via a closed wrapper.

import P2PCoreBytes
import P2PCoreCrypto
import P2PCoreDER
#if hasFeature(Embedded)
import P2PCrypto
#endif

// MARK: - Raw r||s <-> DER SEQUENCE { INTEGER r, INTEGER s }

/// Shared fixed-width-scalar <-> DER conversion for the Embedded ECDSA wrappers.
///
/// `scalarLength` is the curve's coordinate size (32 for P-256, 48 for P-384); a
/// raw ECDSA signature is exactly `2 * scalarLength` bytes (`r || s`).
///
/// Dual-built (NOT Embedded-gated) so the host build can cross-check that this DER
/// encoding is byte-identical to CryptoKit's `derRepresentation` for the same
/// `r || s` (the CertificateVerify interop oracle). The Boring-backed signature
/// schemes that *use* it are Embedded-only.
public enum EmbeddedECDSADER {

    /// DER-encode a raw `r || s` signature as `SEQUENCE { INTEGER r, INTEGER s }`.
    /// `DERWriter.encodeInteger` applies the ASN.1 minimal/sign-bit rules, so the
    /// output matches CryptoKit's `derRepresentation` byte-for-byte.
    ///
    /// - Throws: ``CryptoError/invalidLength`` if `raw` is not `2 * scalarLength`
    ///   bytes (the backend must emit a fixed-width p1363 signature; anything else
    ///   is a backend invariant violation, never silently re-shaped).
    public static func encode(raw: [UInt8], scalarLength: Int) throws(CryptoError) -> [UInt8] {
        guard raw.count == 2 * scalarLength else {
            throw .invalidLength(expected: 2 * scalarLength, actual: raw.count)
        }
        let r = Array(raw[0..<scalarLength])
        let s = Array(raw[scalarLength..<(2 * scalarLength)])
        return DERWriter.sequence([
            DERWriter.encodeInteger(r),
            DERWriter.encodeInteger(s),
        ])
    }

    /// DER-decode `SEQUENCE { INTEGER r, INTEGER s }` back to a fixed-width raw
    /// `r || s` of `2 * scalarLength` bytes. Each INTEGER is left-padded (or its
    /// ASN.1 sign byte dropped) to exactly `scalarLength` bytes.
    ///
    /// Returns `nil` for any malformed DER, trailing bytes, or an integer that does
    /// not fit `scalarLength` (e.g. an over-long `r`/`s`) — the caller treats this
    /// as an invalid signature (`false`), never a silent accept.
    public static func decode(der: [UInt8], scalarLength: Int) -> [UInt8]? {
        var reader = DERReader(der)
        var rBytes = [UInt8]()
        var sBytes = [UInt8]()
        do {
            try reader.readConstructed(.sequence) { (inner) throws(DERError) in
                rBytes = try inner.readIntegerBytes()
                sBytes = try inner.readIntegerBytes()
            }
        } catch {
            return nil
        }
        // The whole input must be exactly one SEQUENCE (no trailing bytes).
        guard reader.isAtEnd else { return nil }
        guard let r = fixedWidth(rBytes, length: scalarLength),
              let s = fixedWidth(sBytes, length: scalarLength) else {
            return nil
        }
        var raw = [UInt8]()
        raw.reserveCapacity(2 * scalarLength)
        raw.append(contentsOf: r)
        raw.append(contentsOf: s)
        return raw
    }

    /// Normalise an ASN.1 INTEGER's content bytes to a fixed-width big-endian
    /// scalar: drop a leading `0x00` sign byte, then left-pad with zeros to
    /// `length`. Returns `nil` if the significant value exceeds `length` bytes.
    private static func fixedWidth(_ integer: [UInt8], length: Int) -> [UInt8]? {
        var value = integer
        // Drop ASN.1 sign byte(s): a leading 0x00 only carries the sign bit.
        while value.count > 1 && value[0] == 0x00 {
            value.removeFirst()
        }
        guard value.count <= length else { return nil }
        if value.count == length { return value }
        var padded = [UInt8](repeating: 0, count: length - value.count)
        padded.append(contentsOf: value)
        return padded
    }
}

#if hasFeature(Embedded)

// MARK: - Span -> [UInt8] (one bulk copy, Embedded-clean)

extension Span where Element == UInt8 {
    /// A fresh `[UInt8]` copy of the span via one `memcpy`-class fill.
    @inline(__always)
    fileprivate func embeddedDERArray() -> [UInt8] {
        let n = count
        guard n > 0 else { return [] }
        return [UInt8](unsafeUninitializedCapacity: n) { destination, initializedCount in
            withUnsafeBufferPointer { source in
                destination.baseAddress!.update(from: source.baseAddress!, count: n)
            }
            initializedCount = n
        }
    }
}

// MARK: - Embedded DER ECDSA P-256

/// ECDSA over P-256 with **DER** signatures for the TLS 1.3 CertificateVerify wire
/// (RFC 8446 §4.2.3), backed by the Embedded `BoringP256Signature`. Keys use the
/// same raw representations as the host scheme: a 32-byte scalar (signing) and a
/// 65-byte X9.62 uncompressed point (verifying).
public enum EmbeddedDERP256Signature: P2PCoreCrypto.SignatureScheme {
    private static let scalarLength = 32

    public struct SigningKey: Sendable {
        let inner: BoringP256Signature.SigningKey
    }

    public struct VerifyingKey: Sendable {
        let inner: BoringP256Signature.VerifyingKey
    }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        SigningKey(inner: try BoringP256Signature.generateSigningKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        SigningKey(inner: try BoringP256Signature.signingKey(rawRepresentation: rawRepresentation))
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        VerifyingKey(inner: try BoringP256Signature.verifyingKey(rawRepresentation: rawRepresentation))
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(inner: BoringP256Signature.verifyingKey(for: signingKey.inner))
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        BoringP256Signature.rawRepresentation(of: signingKey.inner)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        BoringP256Signature.rawRepresentation(of: verifyingKey.inner)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] {
        let raw = try BoringP256Signature.sign(message, with: signingKey.inner)
        return try EmbeddedECDSADER.encode(raw: raw, scalarLength: scalarLength)
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard let raw = EmbeddedECDSADER.decode(der: signature.embeddedDERArray(), scalarLength: scalarLength) else {
            return false
        }
        return BoringP256Signature.isValid(signature: raw.span, for: message, with: verifyingKey.inner)
    }
}

// MARK: - Embedded DER ECDSA P-384

/// ECDSA over P-384 with **DER** signatures for the TLS 1.3 CertificateVerify wire
/// (RFC 8446 §4.2.3), backed by the Embedded `BoringP384Signature`. See
/// ``EmbeddedDERP256Signature`` for the DER-vs-raw rationale.
public enum EmbeddedDERP384Signature: P2PCoreCrypto.SignatureScheme {
    private static let scalarLength = 48

    public struct SigningKey: Sendable {
        let inner: BoringP384Signature.SigningKey
    }

    public struct VerifyingKey: Sendable {
        let inner: BoringP384Signature.VerifyingKey
    }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        SigningKey(inner: try BoringP384Signature.generateSigningKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        SigningKey(inner: try BoringP384Signature.signingKey(rawRepresentation: rawRepresentation))
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        VerifyingKey(inner: try BoringP384Signature.verifyingKey(rawRepresentation: rawRepresentation))
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(inner: BoringP384Signature.verifyingKey(for: signingKey.inner))
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        BoringP384Signature.rawRepresentation(of: signingKey.inner)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        BoringP384Signature.rawRepresentation(of: verifyingKey.inner)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] {
        let raw = try BoringP384Signature.sign(message, with: signingKey.inner)
        return try EmbeddedECDSADER.encode(raw: raw, scalarLength: scalarLength)
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard let raw = EmbeddedECDSADER.decode(der: signature.embeddedDERArray(), scalarLength: scalarLength) else {
            return false
        }
        return BoringP384Signature.isValid(signature: raw.span, for: message, with: verifyingKey.inner)
    }
}

#endif // hasFeature(Embedded)
