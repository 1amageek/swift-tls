/// DTLS Handshake Message Reassembly Buffer (RFC 6347 §4.2.3)
///
/// Collects fragmented DTLS handshake messages and returns the complete
/// message once all fragments have arrived. Handles out-of-order delivery
/// and overlapping fragments.

import P2PCoreBytes

/// Reassembly buffer for fragmented DTLS handshake messages.
public struct HandshakeReassemblyBuffer: Sendable {

    /// Maximum total length (bytes) of a single handshake message we will buffer.
    /// DTLS handshake messages (certificate chains in particular) are large but
    /// bounded; an attacker-controlled 24-bit length field (up to ~16 MB) must not
    /// trigger an eager allocation of that size. 64 KiB comfortably covers a typical
    /// certificate chain while capping the per-message memory commitment.
    public static let maxMessageLength: UInt32 = 64 * 1024

    /// Maximum number of distinct messages being reassembled concurrently. Bounds
    /// the number of buffers an attacker can force open by sending many partial
    /// messages with distinct message_seq values.
    public static let maxConcurrentReassemblies = 16

    /// A message being reassembled from fragments
    struct PendingMessage: Sendable {
        let messageType: DTLSHandshakeType
        let totalLength: UInt32
        var received: [UInt8]
        var coverage: [(offset: UInt32, length: UInt32)]

        init(messageType: DTLSHandshakeType, totalLength: UInt32) {
            self.messageType = messageType
            self.totalLength = totalLength
            self.received = [UInt8](repeating: 0, count: Int(totalLength))
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
    /// - Returns: The complete reassembled message (header + body) once all
    ///   fragments have arrived, or `nil` while more fragments are still expected.
    /// - Throws: `DTLSError.invalidFormat` for an unparseable/inconsistent fragment
    ///   (no silent skip), or `DTLSError.reassemblyLimitExceeded` when the message
    ///   length or concurrent-reassembly cap is exceeded.
    @discardableResult
    public mutating func addFragment(header: DTLSHandshakeHeader, body: [UInt8]) throws(DTLSWireError) -> [UInt8]? {
        // Cap the declared total length BEFORE any allocation, so an attacker cannot
        // force a multi-megabyte eager allocation from a 24-bit length field.
        guard header.length <= Self.maxMessageLength else {
            throw DTLSWireError.dtls(.reassemblyLimitExceeded(
                "message length \(header.length) exceeds maximum \(Self.maxMessageLength)"
            ))
        }

        // Validate fragment bounds (check for overflow).
        guard header.fragmentOffset <= header.length,
              header.fragmentLength <= header.length - header.fragmentOffset else {
            throw DTLSWireError.dtls(.invalidFormat(
                "fragment extends beyond message length (offset=\(header.fragmentOffset), len=\(header.fragmentLength), total=\(header.length))"
            ))
        }

        guard body.count == Int(header.fragmentLength) else {
            throw DTLSWireError.dtls(.invalidFormat(
                "fragment body size \(body.count) does not match declared fragment length \(header.fragmentLength)"
            ))
        }

        // Non-fragmented message: return immediately.
        if !header.isFragmented {
            return try DTLSHandshakeHeader.encodeMessage(
                type: header.messageType,
                messageSeq: header.messageSeq,
                body: body
            )
        }

        // Get or create the pending message. Creating a NEW buffer is the only path
        // that can grow concurrent reassembly state, so enforce the concurrency cap
        // here (before allocating the per-message buffer).
        var message: PendingMessage
        if let existing = pending[header.messageSeq] {
            message = existing
        } else {
            guard pending.count < Self.maxConcurrentReassemblies else {
                throw DTLSWireError.dtls(.reassemblyLimitExceeded(
                    "concurrent reassemblies \(pending.count) reached maximum \(Self.maxConcurrentReassemblies)"
                ))
            }
            message = PendingMessage(
                messageType: header.messageType,
                totalLength: header.length
            )
        }

        // Validate consistency with existing fragments.
        guard message.messageType == header.messageType,
              message.totalLength == header.length else {
            throw DTLSWireError.dtls(.invalidFormat(
                "inconsistent fragment for message_seq \(header.messageSeq) (type/length mismatch)"
            ))
        }

        // Copy fragment data into the correct position.
        let startIndex = Int(header.fragmentOffset)
        let endIndex = startIndex + Int(header.fragmentLength)
        message.received.replaceSubrange(startIndex..<endIndex, with: body)

        // Record coverage.
        message.coverage.append((header.fragmentOffset, header.fragmentLength))

        // Check if complete.
        if message.isComplete {
            pending.removeValue(forKey: header.messageSeq)
            return try DTLSHandshakeHeader.encodeMessage(
                type: header.messageType,
                messageSeq: header.messageSeq,
                body: message.received
            )
        }

        // Store the updated message and wait for more fragments.
        pending[header.messageSeq] = message
        return nil
    }

    /// Split a DTLS handshake record payload into its constituent handshake
    /// message fragments.
    ///
    /// A single DTLS record may pack multiple handshake messages (each a 12-byte
    /// header + fragment body) back to back (RFC 6347 §4.2.3). This parses them
    /// in wire order without performing reassembly, so the caller can feed each
    /// fragment to `addFragment` individually.
    ///
    /// - Parameter recordFragment: The decrypted handshake record payload.
    /// - Returns: The parsed `(header, body)` fragments in wire order.
    /// - Throws: `DTLSError.invalidFormat` if the payload is truncated, contains a
    ///   trailing partial fragment, or a fragment is internally inconsistent
    ///   (no silent skip of leftover bytes).
    public static func parseMessages(
        from recordFragment: [UInt8]
    ) throws(DTLSWireError) -> [(header: DTLSHandshakeHeader, body: [UInt8])] {
        var reader = ByteReader(recordFragment)
        var messages: [(header: DTLSHandshakeHeader, body: [UInt8])] = []

        while !reader.isAtEnd {
            // A complete fragment requires at least the 12-byte header.
            guard reader.remaining >= DTLSHandshakeHeader.headerSize else {
                throw DTLSWireError.dtls(.invalidFormat(
                    "trailing \(reader.remaining) bytes too short for a handshake header"
                ))
            }

            let header = try DTLSHandshakeHeader.decode(reader: &reader)

            guard reader.remaining >= Int(header.fragmentLength) else {
                throw DTLSWireError.dtls(.invalidFormat(
                    "handshake fragment body truncated (need \(header.fragmentLength), have \(reader.remaining))"
                ))
            }

            let body = try reader.dReadBytes(Int(header.fragmentLength))
            messages.append((header, body))
        }

        return messages
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
