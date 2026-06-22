/// Typed errors raised by the Embedded-clean TLS 1.3 key schedule.
///
/// Mirrors the adapter's `TLSKeyScheduleError` so the bridge maps cleanly, and
/// carries the underlying ``P2PCoreCrypto/CryptoError`` for HKDF-Expand failures
/// rather than swallowing them (no silent fallback).
///
/// Embedded-clean: no Foundation, no `any`, closed enum, typed throws.

import P2PCoreCrypto

/// Errors from `TLSCryptoCore` key-schedule operations.
public enum TLSKeyScheduleCoreError: Error, Equatable, Sendable {
    /// The key schedule was used out of order (e.g. application secrets
    /// requested before handshake secrets).
    case invalidState

    /// A crypto-seam primitive failed (HKDF-Expand length overflow, etc.).
    case crypto(CryptoError)
}
