import SSLCore
import SSLTLS

/// The compatibility result of feeding received bytes into a stream session.
///
/// `swift-ssl` keeps one owned byte backing and checked ranges for every batch.
/// This value materializes arrays only at the old session-package boundary; the
/// canonical mechanism and its internal adapters remain range based.
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

enum CanonicalTLSProjection {
    static func output(
        _ output: borrowing TLS13HandshakeOutput
    ) throws(TLSError) -> TLSOutput {
        var bytesToSend: [UInt8] = []
        var applicationData: [UInt8] = []
        var handshakeComplete = false
        var peerClosed = false

        for action in output.actions {
            switch action {
            case .emitRecordBytes(let range):
                do {
                    try output.bytes.withBorrowedBytes { bytes throws(TLSError) in
                        let slice = try bytes.extracting(range.offset..<range.endOffset)
                        append(slice, to: &bytesToSend)
                    }
                } catch let error as TLSError {
                    throw error
                } catch {
                    throw .bufferOverflow
                }
            case .deliverApplicationData(let range, _):
                do {
                    try output.bytes.withBorrowedBytes { bytes throws(TLSError) in
                        let slice = try bytes.extracting(range.offset..<range.endOffset)
                        append(slice, to: &applicationData)
                    }
                } catch let error as TLSError {
                    throw error
                } catch {
                    throw .bufferOverflow
                }
            case .sendAlert(let alert):
                if alert == .closeNotify {
                    peerClosed = true
                }
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
