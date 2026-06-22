/// Typed errors for the Embedded-clean DTLS 1.2 record-protection core.
///
/// Embedded-clean: no Foundation, no `any`, no `String` payloads (so the enum is
/// `Equatable`). AEAD failures from the `CryptoProvider.AEAD` seam
/// (``P2PCoreCrypto/CryptoError``) are surfaced rather than swallowed — there is
/// **no silent fallback**: an open failure throws ``decryptionFailed``, never a
/// garbage/empty plaintext. The adapter bridges these to the existing
/// `DTLSRecordError` (`encryptionFailed`/`decryptionFailed` with messages) so the
/// public behavior is unchanged.

import P2PCoreCrypto

/// Errors raised by ``DTLSRecordProtector``.
public enum DTLSRecordProtectionError: Error, Equatable, Sendable {
    /// The fixed IV passed at construction was not 4 bytes (RFC 5288).
    case invalidFixedIVLength(expected: Int, actual: Int)

    /// The explicit nonce passed to `seal` was not 8 bytes.
    case invalidExplicitNonceLength(expected: Int, actual: Int)

    /// The ciphertext was shorter than explicit-nonce + tag overhead.
    case ciphertextTooShort(minimum: Int, actual: Int)

    /// AEAD decryption/authentication failed. Uniform surface — does not leak why
    /// the record was rejected (RFC 6347 §4.1.2.7).
    case decryptionFailed

    /// A seal (encryption) primitive behind the `CryptoProvider.AEAD` seam failed.
    /// Wraps the typed ``P2PCoreCrypto/CryptoError`` (seal failures are not
    /// security-sensitive and are reported precisely, unlike open failures).
    case crypto(CryptoError)
}
