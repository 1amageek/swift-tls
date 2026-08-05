import SSLCore
import SSLTLS

/// The compatibility result of feeding received bytes into a stream session.
///
/// `swift-ssl` keeps one owned byte backing and checked ranges for every batch.
/// This value materializes arrays only at the public compatibility boundary;
/// the canonical mechanism and its internal adapters remain range based.
public struct TLSOutput: Sendable {
    /// Bytes to write back to the peer over the TLS byte stream (handshake
    /// responses, encrypted alerts). Empty when there is nothing to send.
    public let bytesToSend: [UInt8]

    /// Decrypted application data received from the peer. Empty when none.
    public let applicationData: [UInt8]

    /// `true` iff the handshake completed during this `receive(_:)` call.
    public let handshakeComplete: Bool

    /// `true` iff the receive path reports a peer close_notify in this call.
    public let peerClosed: Bool

    /// `true` iff a TLS 1.3 NewSessionTicket was accepted in this call. The
    /// move-only state is retrieved from the session with
    /// ``TLSClient/takeResumptionState()``.
    public let sessionTicketReceived: Bool

    /// A terminal external capability request, if the TLS engine suspended
    /// after producing this output batch. The caller must answer it with the
    /// matching token before calling `resume(_:)`.
    public let capabilityRequest: TLSCapabilityRequest?

    public init(
        bytesToSend: [UInt8] = [],
        applicationData: [UInt8] = [],
        handshakeComplete: Bool = false,
        peerClosed: Bool = false,
        sessionTicketReceived: Bool = false,
        capabilityRequest: TLSCapabilityRequest? = nil
    ) {
        self.bytesToSend = bytesToSend
        self.applicationData = applicationData
        self.handshakeComplete = handshakeComplete
        self.peerClosed = peerClosed
        self.sessionTicketReceived = sessionTicketReceived
        self.capabilityRequest = capabilityRequest
    }
}

enum CanonicalTLSProjection {
    static func array(from bytes: borrowing OwnedBytes) -> [UInt8] {
        bytes.withBorrowedBytes { span in
            var result: [UInt8] = []
            result.reserveCapacity(span.count)
            var index = 0
            while index < span.count {
                result.append(span[index])
                index += 1
            }
            return result
        }
    }

    static func output(
        _ output: borrowing TLS13HandshakeOutput
    ) throws(TLSError) -> TLSOutput {
        var bytesToSend: [UInt8] = []
        var applicationData: [UInt8] = []
        var handshakeComplete = false
        let peerClosed = false

        for action in output.actions {
            switch action {
            case .emitRecordBytes(let range):
                try output.bytes.withBorrowedBytes { bytes throws(TLSError) in
                    let slice = bytes.extracting(range.offset..<range.endOffset)
                    append(slice, to: &bytesToSend)
                }
            case .deliverApplicationData(let range, _):
                try output.bytes.withBorrowedBytes { bytes throws(TLSError) in
                    let slice = bytes.extracting(range.offset..<range.endOffset)
                    append(slice, to: &applicationData)
                }
            case .sendAlert(let alert):
                // `sendAlert` describes an alert emitted by this endpoint.
                // It is not evidence that the peer sent close_notify; the
                // stream core currently exposes no peer-close action here.
                _ = alert
            case .handshakeComplete:
                handshakeComplete = true
            case .handshakeConfirmed, .earlyDataAccepted, .earlyDataRejected:
                break
            }
        }

        return TLSOutput(
            bytesToSend: bytesToSend,
            applicationData: applicationData,
            handshakeComplete: handshakeComplete,
            peerClosed: peerClosed
        )
    }

    static func transition(
        _ transition: consuming TLS13StreamHandshakeTransition
    ) throws(TLSError) -> TLSOutput {
        switch consume transition {
        case .output(let output):
            return try self.output(output)
        case .suspended(let request, let output):
            var projected = try self.output(output)
            projected = TLSOutput(
                bytesToSend: projected.bytesToSend,
                applicationData: projected.applicationData,
                handshakeComplete: projected.handshakeComplete,
                peerClosed: projected.peerClosed,
                sessionTicketReceived: projected.sessionTicketReceived,
                capabilityRequest: TLSCapabilityRequest(core: request)
            )
            return projected
        }
    }

    private static func append(_ bytes: Span<UInt8>, to output: inout [UInt8]) {
        var index = 0
        while index < bytes.count {
            output.append(bytes[index])
            index += 1
        }
    }

    static func bytesToSend(
        _ output: borrowing TLS13HandshakeOutput
    ) throws(TLSError) -> [UInt8] {
        try self.output(output).bytesToSend
    }

    static func applicationData(
        _ output: borrowing TLS13HandshakeOutput
    ) throws(TLSError) -> [UInt8] {
        try self.output(output).applicationData
    }
}
