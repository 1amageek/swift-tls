/// The aggregate effect of feeding received bytes into a TLS/DTLS engine.
///
/// A single `receive(_:)` can produce several effects at once during a TLS 1.3
/// handshake (bytes to send back, decrypted application data, the
/// handshake-complete transition, a received peer-close). The engine returns one
/// aggregate value rather than a stream of single events. Every effect is
/// surfaced — nothing is silently dropped.
///
/// Embedded-clean: `[UInt8]` currency, no Foundation, value type.
public struct TLSEngineOutput: Sendable {
    /// Bytes to write back to the peer over the byte stream (handshake responses,
    /// encrypted alerts). Empty when there is nothing to send.
    public var bytesToSend: [UInt8]

    /// Decrypted application data received from the peer. Empty when none.
    public var applicationData: [UInt8]

    /// `true` iff the handshake completed during this `receive(_:)` call.
    public var handshakeComplete: Bool

    /// `true` iff the peer sent a close_notify (graceful shutdown) in this call.
    public var peerClosed: Bool

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
