/// Typed errors raised by the Embedded-clean TLS 1.3 (EC)DHE key exchange.
///
/// Carries the underlying ``P2PCoreCrypto/CryptoError`` for seam failures rather
/// than swallowing them (no silent fallback). The `unsupportedGroup` case covers
/// named groups the core does not handle (e.g. the X25519MLKEM768 hybrid, which
/// has no place in the DH-only ``P2PCoreCrypto/KeyAgreement`` seam and stays in
/// the adapter).
///
/// Embedded-clean: no Foundation, no `any`, closed enum, typed throws.

import P2PCoreCrypto

/// Errors from `TLSCryptoCore` (EC)DHE key-exchange operations.
public enum TLSKeyExchangeCoreError: Error, Equatable, Sendable {
    /// The named group is not one of X25519 / P-256 / P-384 (the only groups
    /// expressible through the DH key-agreement seam).
    case unsupportedGroup

    /// The peer key share had the wrong length for the named group.
    case invalidPublicKeyLength(expected: Int, actual: Int)

    /// A crypto-seam key-agreement primitive failed (bad peer key, etc.).
    case crypto(CryptoError)
}
