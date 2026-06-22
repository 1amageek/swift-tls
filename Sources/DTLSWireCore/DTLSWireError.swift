/// Unified typed-throws error for the Embedded-clean DTLS wire codec.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// DTLS wire codec uses typed throws with this single error type. It wraps the two
/// error kinds the codec can raise:
/// - ``ByteError`` from the `P2PCoreBytes` reader/writer,
/// - ``DTLSError`` for malformed message structure / handshake violations.
///
/// The `DTLSCore` adapter unwraps this back to the original concrete error type at
/// the `Data`-based boundary, so callers (and the existing test suite) continue to
/// catch `DTLSError` / `ByteError` directly.

import P2PCoreBytes

public enum DTLSWireError: Error, Sendable {
    case bytes(ByteError)
    case dtls(DTLSError)
}
