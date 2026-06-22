/// Typed errors for the Embedded-clean TLS 1.3 record-protection core.
///
/// Embedded-clean: no Foundation, no `any`. AEAD failures from the
/// `CryptoProvider.AEAD` seam (``P2PCoreCrypto/CryptoError``) are surfaced rather
/// than swallowed — there is **no silent fallback**. To preserve the exact
/// decrypt-failure behavior of the legacy `TLSRecordCryptor` (any AEAD-open
/// failure is reported uniformly as a bad record MAC, RFC 8446 §5.2 — padding
/// oracle prevention), an open failure is normalized to ``badRecordMac`` by the
/// protector, never to a distinguishable error and never to a garbage plaintext.

import P2PCoreCrypto

/// Errors raised by ``TLSRecordProtector``.
public enum TLSRecordProtectionError: Error, Equatable, Sendable {
    /// The IV passed at construction was not 12 bytes (RFC 8446 §5.3).
    case invalidIVLength(expected: Int, actual: Int)

    /// The plaintext exceeded the maximum TLS record fragment size.
    case plaintextTooLarge(Int)

    /// The sequence number would overflow `UInt64`; a key update is required
    /// (RFC 8446 §5.3). Carries no value because the failing operation aborts
    /// before consuming the sequence number.
    case sequenceNumberOverflow

    /// The ciphertext was shorter than the AEAD authentication tag.
    case ciphertextTooShort(minimum: Int, actual: Int)

    /// AEAD decryption/authentication failed (RFC 8446 §5.2 "bad_record_mac").
    /// All underlying ``P2PCoreCrypto/CryptoError`` open failures collapse to this
    /// single case so the failure surface never leaks why a record was rejected.
    case badRecordMac

    /// The decrypted inner plaintext had no non-zero content-type byte
    /// (RFC 8446 §5.2 inner plaintext = content || content_type || zeros).
    case invalidInnerPlaintext

    /// A seal (encryption) primitive behind the `CryptoProvider.AEAD` seam failed.
    /// Wraps the typed ``P2PCoreCrypto/CryptoError`` (seal failures are not
    /// security-sensitive and are reported precisely, unlike open failures).
    case crypto(CryptoError)
}
