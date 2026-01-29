/// DTLS Anti-Replay Window (RFC 6347 §4.1.2.6)
///
/// Implements a 64-bit sliding window for replay protection.
/// Tracks the highest received sequence number and maintains a bitmap
/// of recently received sequence numbers within the window.
///
/// This prevents attackers from replaying old DTLS records.

import Foundation

/// RFC 6347 §4.1.2.6 sliding window anti-replay protection.
/// Window size is 64 bits, tracking the highest received sequence number
/// and a bitmap of recent sequence numbers within the window.
public struct AntiReplayWindow: Sendable {

    /// The highest sequence number received so far
    private var highestSeq: UInt64 = 0

    /// Bitmap tracking which of the last 64 sequence numbers have been received
    /// Bit 0 = highestSeq, bit 1 = highestSeq-1, etc.
    private var bitmap: UInt64 = 0

    /// Whether any packet has been received yet
    private var initialized: Bool = false

    /// Window size (64 bits)
    public static let windowSize: UInt64 = 64

    public init() {}

    /// Check if a sequence number should be accepted.
    /// Returns true if the sequence number is new (not a replay).
    ///
    /// - Parameter sequenceNumber: The 48-bit sequence number from the DTLS record
    /// - Returns: true if the packet should be accepted, false if it's a replay or too old
    public mutating func shouldAccept(sequenceNumber: UInt64) -> Bool {
        // First packet initializes the window
        if !initialized {
            initialized = true
            highestSeq = sequenceNumber
            bitmap = 1  // Mark current sequence as received
            return true
        }

        // New highest sequence number
        if sequenceNumber > highestSeq {
            let diff = sequenceNumber - highestSeq

            if diff < Self.windowSize {
                // Shift bitmap and mark new sequence
                bitmap = bitmap << diff
                bitmap |= 1
            } else {
                // Gap too large - reset bitmap
                bitmap = 1
            }

            highestSeq = sequenceNumber
            return true
        }

        // Sequence number within or before the window
        let diff = highestSeq - sequenceNumber

        // Too old - outside the window
        if diff >= Self.windowSize {
            return false
        }

        // Check if already received (replay)
        let bit: UInt64 = 1 << diff
        if bitmap & bit != 0 {
            return false  // Duplicate - replay detected
        }

        // Mark as received and accept
        bitmap |= bit
        return true
    }

    /// Reset the window (e.g., on epoch change)
    public mutating func reset() {
        highestSeq = 0
        bitmap = 0
        initialized = false
    }

    /// The current highest received sequence number
    public var currentHighest: UInt64 {
        highestSeq
    }

    /// Whether the window has been initialized (any packet received)
    public var isInitialized: Bool {
        initialized
    }

    /// Check if a sequence number has already been received (without modifying state)
    /// Used for preliminary replay check before decryption
    public func isReceived(sequenceNumber: UInt64) -> Bool {
        guard initialized else { return false }

        if sequenceNumber > highestSeq {
            return false  // New sequence, not yet received
        }

        let diff = highestSeq - sequenceNumber
        if diff >= Self.windowSize {
            return false  // Outside window, treat as not received (will be rejected anyway)
        }

        let bit: UInt64 = 1 << diff
        return (bitmap & bit) != 0
    }
}
