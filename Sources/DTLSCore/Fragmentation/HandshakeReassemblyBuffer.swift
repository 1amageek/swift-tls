/// DTLS Handshake Message Reassembly Buffer (RFC 6347 §4.2.3)
///
/// Collects fragmented DTLS handshake messages and returns the complete
/// message once all fragments have arrived. Handles out-of-order delivery
/// and overlapping fragments.

import Foundation
import TLSCore

/// Reassembly buffer for fragmented DTLS handshake messages.
public struct HandshakeReassemblyBuffer: Sendable {

    /// A message being reassembled from fragments
    struct PendingMessage: Sendable {
        let messageType: DTLSHandshakeType
        let totalLength: UInt32
        var received: Data
        var coverage: [(offset: UInt32, length: UInt32)]

        init(messageType: DTLSHandshakeType, totalLength: UInt32) {
            self.messageType = messageType
            self.totalLength = totalLength
            self.received = Data(count: Int(totalLength))
            self.coverage = []
        }

        /// Check if all bytes have been received
        var isComplete: Bool {
            // Merge overlapping ranges and check if they cover [0, totalLength)
            let merged = Self.mergeRanges(coverage)
            guard merged.count == 1 else { return false }
            let range = merged[0]
            return range.offset == 0 && range.length == totalLength
        }

        /// Merge overlapping/adjacent ranges into minimal set
        static func mergeRanges(_ ranges: [(offset: UInt32, length: UInt32)]) -> [(offset: UInt32, length: UInt32)] {
            guard !ranges.isEmpty else { return [] }

            let sorted = ranges.sorted { $0.offset < $1.offset }
            var merged: [(offset: UInt32, length: UInt32)] = []

            for range in sorted {
                if merged.isEmpty {
                    merged.append(range)
                } else {
                    let last = merged[merged.count - 1]
                    let lastEnd = last.offset + last.length
                    let rangeEnd = range.offset + range.length

                    // Check for overlap or adjacency
                    if range.offset <= lastEnd {
                        // Merge: extend last range if needed
                        let newEnd = max(lastEnd, rangeEnd)
                        merged[merged.count - 1] = (last.offset, newEnd - last.offset)
                    } else {
                        merged.append(range)
                    }
                }
            }

            return merged
        }
    }

    /// Pending messages keyed by message sequence number
    private var pending: [UInt16: PendingMessage] = [:]

    public init() {}

    /// Add a fragment to the reassembly buffer.
    ///
    /// - Parameters:
    ///   - header: The DTLS handshake header (contains fragment info)
    ///   - body: The fragment body data
    /// - Returns: The complete reassembled message (header + body) if all fragments received, nil otherwise
    public mutating func addFragment(header: DTLSHandshakeHeader, body: Data) -> Data? {
        // Validate fragment bounds (check for overflow)
        guard header.fragmentOffset <= header.length,
              header.fragmentLength <= header.length - header.fragmentOffset else {
            // Invalid fragment - extends beyond total length or would overflow
            return nil
        }

        guard body.count == Int(header.fragmentLength) else {
            // Body size doesn't match declared fragment length
            return nil
        }

        // Non-fragmented message: return immediately
        if !header.isFragmented {
            return DTLSHandshakeHeader.encodeMessage(
                type: header.messageType,
                messageSeq: header.messageSeq,
                body: body
            )
        }

        // Get or create pending message
        var message = pending[header.messageSeq] ?? PendingMessage(
            messageType: header.messageType,
            totalLength: header.length
        )

        // Validate consistency with existing fragments
        guard message.messageType == header.messageType,
              message.totalLength == header.length else {
            // Inconsistent fragment - different type or length
            return nil
        }

        // Copy fragment data into correct position
        let startIndex = message.received.startIndex + Int(header.fragmentOffset)
        let endIndex = startIndex + Int(header.fragmentLength)
        message.received.replaceSubrange(startIndex..<endIndex, with: body)

        // Record coverage
        message.coverage.append((header.fragmentOffset, header.fragmentLength))

        // Check if complete
        if message.isComplete {
            pending.removeValue(forKey: header.messageSeq)
            return DTLSHandshakeHeader.encodeMessage(
                type: header.messageType,
                messageSeq: header.messageSeq,
                body: message.received
            )
        }

        // Store updated message and wait for more fragments
        pending[header.messageSeq] = message
        return nil
    }

    /// Clear all pending fragments (e.g., on handshake restart)
    public mutating func clear() {
        pending.removeAll()
    }

    /// Number of messages currently being reassembled
    public var pendingCount: Int {
        pending.count
    }
}
