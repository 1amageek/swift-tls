/// The single public error type for the `TLS` facade.
///
/// The clean break folds swift-tls's ~20 implementation-level error enums
/// (`TLSConnectionError`, `TLSHandshakeError`, `TLSRecordError`,
/// `TLSConfigurationError`, `TLSError` (engine), `DTLSConnectionError`, …) into
/// ONE public, closed, typed-throws enum so a facade caller has a single
/// exhaustive `catch`. Fine-grained codec errors stay package/internal to the
/// engines and the Tier-3 `TLSWire`/`DTLSWire` codecs.

/// Errors surfaced by `TLSClient`/`TLSServer`/`DTLSClient`/`DTLSServer`.
public enum TLSError: Error, Equatable, Sendable {
    /// The handshake is not complete; application data cannot be sent yet.
    case handshakeNotComplete
    /// The connection has been closed (locally or by a received close_notify).
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
    /// An internal invariant was violated; `reason` describes it.
    case internalError(reason: String)
}
