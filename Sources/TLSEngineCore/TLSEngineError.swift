/// The single typed-throws error surface of the TLS/DTLS engines.
///
/// The engine collapses the underlying core errors (``TLSWireCore/TLSHandshakeError``,
/// ``TLSRecordCore/TLSRecordProtectionError``, key-schedule/key-exchange/signature
/// core errors) into ONE closed enum so a caller (the facade, the QUIC/libp2p
/// adapters) has a single exhaustive `catch`. No failure is ever silently
/// swallowed — every verification or protocol failure is a typed throw.
///
/// Embedded-clean: no Foundation, no `any`, value type, typed throws. The
/// associated `reason` strings are `StaticString`-free (interpolation works under
/// Embedded for `String`), used for diagnostics only — never to gate control flow.
import TLSWireCore

public enum TLSEngineError: Error, Sendable {
    /// Application data was requested before the handshake completed.
    case handshakeNotComplete
    /// The connection has been closed locally or by a received close_notify.
    case connectionClosed
    /// A fatal handshake/protocol error (negotiation, state machine, parsing).
    case protocolFailure(reason: String)
    /// The peer sent a fatal alert. `code` is the RFC 8446 alert description code.
    case fatalAlert(code: UInt8, reason: String)
    /// Certificate or signature verification failed (fail-closed).
    case verificationFailed(reason: String)
    /// The engine configuration is invalid (e.g. server without identity).
    case invalidConfiguration(reason: String)
    /// An input byte buffer exceeded an internal safety bound (DoS protection).
    case bufferOverflow
    /// An internal invariant was violated; `reason` describes it.
    case internalError(reason: String)

    /// Maps a core handshake error onto the engine surface, preserving the
    /// failure category. Verification failures map to `.verificationFailed`,
    /// everything else to `.protocolFailure` (no silent collapse to success).
    public static func from(handshake error: TLSHandshakeError) -> TLSEngineError {
        switch error {
        case .signatureVerificationFailed:
            return .verificationFailed(reason: "CertificateVerify signature verification failed")
        case .certificateVerificationFailed(let reason):
            return .verificationFailed(reason: reason)
        case .finishedVerificationFailed:
            return .verificationFailed(reason: "Finished MAC verification failed")
        case .downgradeDetected:
            return .verificationFailed(reason: "TLS downgrade detected")
        default:
            return .protocolFailure(reason: "\(error)")
        }
    }
}
