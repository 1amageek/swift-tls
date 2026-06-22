/// Unified typed-throws error for the Embedded-clean wire codec.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// wire codec uses typed throws with this single error type. It wraps the three
/// error kinds the codec can raise:
/// - ``ByteError`` from the `P2PCoreBytes` reader/writer,
/// - ``TLSDecodeError`` for malformed message structure,
/// - ``TLSHandshakeError`` for handshake-level violations (e.g. duplicate
///   extensions, malformed CertificateRequest).
///
/// The `TLSCore` adapter unwraps this back to the original concrete error type at
/// the `Data`-based boundary, so callers (and the existing test suite) continue to
/// catch `TLSDecodeError` / `TLSHandshakeError` / `ByteError` directly.

import P2PCoreBytes

public enum TLSWireError: Error, Sendable {
    case bytes(ByteError)
    case decode(TLSDecodeError)
    case handshake(TLSHandshakeError)
}
