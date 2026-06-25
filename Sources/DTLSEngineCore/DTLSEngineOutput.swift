/// The aggregate effect of feeding a received UDP datagram into a DTLS engine.
///
/// DTLS works over datagrams: a single `receive(_:)` may yield several datagrams
/// to send back (a whole flight), decrypted application data, the
/// handshake-complete transition, a received peer-close, and non-fatal record
/// anomalies. The engine returns one aggregate value rather than a stream of
/// single events. Every effect is surfaced — nothing is silently dropped.
///
/// RFC 6347 §4.1.2.7 mandates that bad records be silently discarded at the wire
/// (no fatal alert), and DTLS robustness requires that one bad record not abort
/// the remaining records in the datagram. Those discards are therefore surfaced
/// here as ``Anomaly`` values, not swallowed.
///
/// Embedded-clean: `[UInt8]` currency, no Foundation, value type. Mirrors
/// ``TLSEngineCore/TLSEngineOutput`` but with the DTLS datagram-list shape.
public struct DTLSEngineOutput: Sendable {
    /// A non-fatal record-level anomaly observed while processing the datagram.
    public enum Anomaly: Sendable, Equatable {
        case authenticationFailed
        case malformed
        case replayed
        case tooOld
        case malformedAlert
    }

    /// Encoded DTLS datagrams to send to the peer. Empty when there is nothing to
    /// send. Each element is one UDP datagram (may pack several records).
    public var datagramsToSend: [[UInt8]]

    /// Decrypted application data received from the peer. Empty when none.
    public var applicationData: [UInt8]

    /// `true` iff the handshake completed during this `receive(_:)` call.
    public var handshakeComplete: Bool

    /// `true` iff the peer sent a close_notify (graceful shutdown) in this call.
    public var peerClosed: Bool

    /// Non-fatal record anomalies observed while processing the datagram.
    public var anomalies: [Anomaly]

    public init(
        datagramsToSend: [[UInt8]] = [],
        applicationData: [UInt8] = [],
        handshakeComplete: Bool = false,
        peerClosed: Bool = false,
        anomalies: [Anomaly] = []
    ) {
        self.datagramsToSend = datagramsToSend
        self.applicationData = applicationData
        self.handshakeComplete = handshakeComplete
        self.peerClosed = peerClosed
        self.anomalies = anomalies
    }
}
