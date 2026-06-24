/// The result of feeding received bytes into a `TLSClient`/`TLSServer`.
///
/// A single `receive(_:)` call can produce several effects at once during a TLS
/// 1.3 handshake (bytes to send back, decrypted application data, and the
/// handshake-complete transition), so the facade returns one aggregate value
/// rather than a stream of single events. Every effect is surfaced — nothing is
/// silently dropped.
public struct TLSOutput: Sendable {
    /// Bytes to write back to the peer over the TLS byte stream (handshake
    /// responses, encrypted alerts). Empty when there is nothing to send.
    public let bytesToSend: [UInt8]

    /// Decrypted application data received from the peer. Empty when none.
    public let applicationData: [UInt8]

    /// `true` iff the handshake completed during this `receive(_:)` call.
    public let handshakeComplete: Bool

    /// `true` iff the peer sent a close_notify (graceful shutdown) in this call.
    public let peerClosed: Bool

    public init(
        bytesToSend: [UInt8] = [],
        applicationData: [UInt8] = [],
        handshakeComplete: Bool = false,
        peerClosed: Bool = false
    ) {
        self.bytesToSend = bytesToSend
        self.applicationData = applicationData
        self.handshakeComplete = handshakeComplete
        self.peerClosed = peerClosed
    }
}
