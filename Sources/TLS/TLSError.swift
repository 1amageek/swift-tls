/// The single public error type for the `TLS` facade.
///
/// The session facade folds mechanism-level failures into one public, closed,
/// typed-throws enum so a caller has a single exhaustive `catch`. Fine-grained
/// codec errors stay package-internal to the `swift-ssl` engines and wire codecs.

/// Errors surfaced by `TLSClient`/`TLSServer`/`DTLSClient`/`DTLSServer`.
public enum TLSError: Error, Equatable, Sendable {
    /// The handshake is not complete; application data cannot be sent yet.
    case handshakeNotComplete
    /// The connection has been closed locally or marked terminal by its engine.
    case connectionClosed
    /// A fatal protocol error occurred; the connection is permanently failed.
    /// `reason` is a human-readable description of the underlying failure.
    case protocolFailure(reason: String)
    /// The peer sent a fatal alert. `code` is the RFC 8446 alert description code.
    case fatalAlert(code: UInt8, reason: String)
    /// Certificate or signature verification failed.
    case verificationFailed(reason: String)
    /// The configuration is invalid (e.g. server without identity material).
    case invalidConfiguration(reason: String)
    /// An input byte buffer exceeded an internal safety bound (DoS protection).
    case bufferOverflow
    /// A read/receive was attempted concurrently with another in-flight receive.
    case concurrentReceiveNotAllowed
    /// A DTLS handshake flight exhausted its bounded retransmission budget.
    case retransmissionLimitExceeded
    /// An internal invariant was violated; `reason` describes it.
    case internalError(reason: String)
    /// A capability response does not match the suspended TLS operation.
    case invalidCapabilityResponse(reason: String)
}
