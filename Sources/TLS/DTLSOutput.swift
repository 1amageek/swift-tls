/// The result of feeding a received UDP datagram into a `DTLSClient`/`DTLSServer`.
///
/// DTLS works over datagrams: a single `receive(_:)` may yield several datagrams
/// to send back, decrypted application data, the handshake-complete transition,
/// and non-fatal record anomalies (RFC 6347 §4.1.2.7 mandates bad records be
/// silently discarded at the wire, but they are surfaced here, not swallowed).
public struct DTLSOutput: Sendable {
    /// A non-fatal record-level anomaly observed while processing the datagram.
    public enum Anomaly: Sendable, Equatable {
        case authenticationFailed
        case malformed
        case replayed
        case tooOld
        case malformedAlert
    }

    /// Encoded DTLS datagrams to send to the peer.
    public let datagramsToSend: [[UInt8]]

    /// Decrypted application data received from the peer.
    public let applicationData: [UInt8]

    /// `true` iff the handshake completed during this `receive(_:)` call.
    public let handshakeComplete: Bool

    /// `true` iff the peer sent a close_notify.
    public let peerClosed: Bool

    /// Non-fatal record anomalies observed while processing the datagram.
    public let anomalies: [Anomaly]

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
