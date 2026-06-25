/// The single typed-throws error surface of the DTLS 1.2 engines.
///
/// The DTLS engine collapses the underlying core errors
/// (``DTLSWireCore/DTLSError``, ``DTLSWireCore/DTLSWireError``,
/// ``DTLSRecordCore/DTLSRecordProtectionError``) into ONE closed enum so a caller
/// (the facade, the WebRTC/libp2p adapters) has a single exhaustive `catch`. No
/// failure is ever silently swallowed — every verification, cookie, replay, or
/// protocol failure is a typed throw.
///
/// Embedded-clean: no Foundation, no `any`, value type, typed throws. The
/// associated `reason` strings are diagnostics only — never used to gate control
/// flow. Mirrors ``TLSEngineCore/TLSEngineError`` so the facade maps both engines
/// onto one `TLSError`.

import DTLSWireCore

public enum DTLSEngineError: Error, Sendable {
    /// The handshake has not been started yet.
    case handshakeNotStarted
    /// Application data was requested before the handshake completed.
    case handshakeNotComplete
    /// The handshake was already started.
    case handshakeAlreadyStarted
    /// The connection has been closed locally or by a received close_notify/fatal.
    case connectionClosed
    /// A fatal handshake/protocol error (negotiation, state machine, parsing).
    case protocolFailure(reason: String)
    /// The peer sent a fatal alert. `code` is the RFC 5246 alert description code.
    case fatalAlert(code: UInt8, reason: String)
    /// Certificate, cookie, or signature verification failed (fail-closed).
    case verificationFailed(reason: String)
    /// The engine configuration is invalid (e.g. server without identity).
    case invalidConfiguration(reason: String)
    /// An input byte buffer exceeded an internal safety bound (DoS protection).
    case bufferOverflow
    /// The retransmission limit was reached without progress.
    case maxRetransmissionsExceeded
    /// An internal invariant was violated; `reason` describes it.
    case internalError(reason: String)

    /// Maps a core DTLS handshake error onto the engine surface, preserving the
    /// failure category. Verification failures map to `.verificationFailed`,
    /// everything else to `.protocolFailure` (no silent collapse to success).
    public static func from(core error: DTLSError) -> DTLSEngineError {
        switch error {
        case .signatureVerificationFailed:
            return .verificationFailed(reason: "DTLS signature verification failed")
        case .verifyDataMismatch:
            return .verificationFailed(reason: "DTLS Finished verify_data mismatch")
        case .cookieMismatch:
            return .verificationFailed(reason: "DTLS HelloVerifyRequest cookie mismatch")
        case .clientCertificateRequired:
            return .verificationFailed(reason: "DTLS client certificate required")
        case .invalidCertificate(let reason):
            return .verificationFailed(reason: reason)
        case .maxRetransmissionsExceeded:
            return .maxRetransmissionsExceeded
        default:
            return .protocolFailure(reason: "\(error)")
        }
    }

    /// Maps a wire-codec error onto the engine surface (always a protocol failure).
    public static func from(wire error: DTLSWireError) -> DTLSEngineError {
        .protocolFailure(reason: "DTLS wire decode failed: \(error)")
    }
}
