/// Anti-Replay Window Tests (RFC 6347 §4.1.2.6)
///
/// Tests the 64-bit sliding window implementation for DTLS replay protection.

import Testing
import Foundation
@testable import DTLSRecord

@Suite("Anti-Replay Window Tests")
struct AntiReplayWindowTests {

    // MARK: - Basic Operations

    @Test("First packet is always accepted")
    func testFirstPacketAccepted() {
        var window = AntiReplayWindow()
        #expect(window.shouldAccept(sequenceNumber: 100) == true)
    }

    @Test("Duplicate packet is rejected")
    func testDuplicateRejected() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)
        #expect(window.shouldAccept(sequenceNumber: 100) == false)
    }

    @Test("New higher sequence is accepted")
    func testHigherSequenceAccepted() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)
        #expect(window.shouldAccept(sequenceNumber: 101) == true)
        #expect(window.shouldAccept(sequenceNumber: 200) == true)
    }

    @Test("Sequential packets all accepted")
    func testSequentialPacketsAccepted() {
        var window = AntiReplayWindow()
        for i: UInt64 in 0..<100 {
            #expect(window.shouldAccept(sequenceNumber: i) == true)
        }
    }

    // MARK: - Window Boundaries

    @Test("Packet within window is accepted")
    func testWithinWindowAccepted() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)
        // Window size is 64, so 100-63=37 is still within window
        #expect(window.shouldAccept(sequenceNumber: 37) == true)
        #expect(window.shouldAccept(sequenceNumber: 50) == true)
    }

    @Test("Packet outside window is rejected")
    func testOutsideWindowRejected() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)
        // 100-64=36 is outside window
        #expect(window.shouldAccept(sequenceNumber: 36) == false)
        #expect(window.shouldAccept(sequenceNumber: 0) == false)
    }

    @Test("Window boundary exact edge case - inside")
    func testWindowBoundaryEdgeInside() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 63)
        // diff = 63 - 0 = 63, which is exactly at the edge (< 64)
        #expect(window.shouldAccept(sequenceNumber: 0) == true)
        // Replay should be rejected
        #expect(window.shouldAccept(sequenceNumber: 0) == false)
    }

    @Test("Window boundary exact edge case - outside")
    func testWindowBoundaryEdgeOutside() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 64)
        // diff = 64 - 0 = 64, which is exactly outside (>= 64)
        #expect(window.shouldAccept(sequenceNumber: 0) == false)
    }

    // MARK: - Bitmap Shifting

    @Test("Large gap resets bitmap correctly")
    func testLargeGapResetsBitmap() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 0)
        _ = window.shouldAccept(sequenceNumber: 5)
        // Large gap (>= 64)
        _ = window.shouldAccept(sequenceNumber: 1000)
        // Old sequence numbers are all outside window
        #expect(window.shouldAccept(sequenceNumber: 5) == false)
        // But recent ones within window are accepted
        #expect(window.shouldAccept(sequenceNumber: 999) == true)
        #expect(window.shouldAccept(sequenceNumber: 950) == true)
    }

    @Test("Bitmap shifts correctly on small increments")
    func testBitmapShiftsCorrectly() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 10)
        _ = window.shouldAccept(sequenceNumber: 12)
        _ = window.shouldAccept(sequenceNumber: 15)

        // 10, 12, 15 are received
        #expect(window.isReceived(sequenceNumber: 10) == true)
        #expect(window.isReceived(sequenceNumber: 12) == true)
        #expect(window.isReceived(sequenceNumber: 15) == true)

        // 11, 13, 14 are not received
        #expect(window.isReceived(sequenceNumber: 11) == false)
        #expect(window.isReceived(sequenceNumber: 13) == false)
        #expect(window.isReceived(sequenceNumber: 14) == false)
    }

    @Test("Bitmap tracks all 64 positions")
    func testBitmapTracks64Positions() {
        var window = AntiReplayWindow()

        // Receive every other packet from 0 to 126
        for i: UInt64 in stride(from: 0, through: 126, by: 2) {
            _ = window.shouldAccept(sequenceNumber: i)
        }

        // Now highest is 126, window covers [63, 126]
        // Check that even numbers in window are marked received
        for i: UInt64 in stride(from: 64, through: 126, by: 2) {
            #expect(window.isReceived(sequenceNumber: i) == true, "Sequence \(i) should be received")
        }

        // Odd numbers in window should not be received
        for i: UInt64 in stride(from: 65, through: 125, by: 2) {
            #expect(window.isReceived(sequenceNumber: i) == false, "Sequence \(i) should not be received")
        }
    }

    // MARK: - Out-of-Order

    @Test("Out-of-order packets within window accepted")
    func testOutOfOrderAccepted() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)
        _ = window.shouldAccept(sequenceNumber: 102)
        _ = window.shouldAccept(sequenceNumber: 101) // Out of order
        #expect(window.isReceived(sequenceNumber: 100) == true)
        #expect(window.isReceived(sequenceNumber: 101) == true)
        #expect(window.isReceived(sequenceNumber: 102) == true)
    }

    @Test("Severely out-of-order within window")
    func testSeverelyOutOfOrder() {
        var window = AntiReplayWindow()

        // Receive 100, then 150, then fill in gaps
        _ = window.shouldAccept(sequenceNumber: 100)
        _ = window.shouldAccept(sequenceNumber: 150)

        // 100 is now outside window (150 - 100 = 50 < 64, so still in)
        #expect(window.shouldAccept(sequenceNumber: 100) == false) // Already received

        // 120 is in window and not received
        #expect(window.shouldAccept(sequenceNumber: 120) == true)
    }

    // MARK: - Reset

    @Test("Reset clears all state")
    func testResetClearsState() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)
        _ = window.shouldAccept(sequenceNumber: 105)
        window.reset()
        #expect(window.isInitialized == false)
        #expect(window.currentHighest == 0)
        // After reset, same sequence numbers are accepted again
        #expect(window.shouldAccept(sequenceNumber: 100) == true)
    }

    // MARK: - isReceived (read-only check)

    @Test("isReceived does not modify state")
    func testIsReceivedDoesNotModifyState() {
        var window = AntiReplayWindow()
        _ = window.shouldAccept(sequenceNumber: 100)

        // Check multiple times - should not affect state
        _ = window.isReceived(sequenceNumber: 50)
        _ = window.isReceived(sequenceNumber: 50)
        _ = window.isReceived(sequenceNumber: 50)

        // 50 should still be acceptable since isReceived didn't mark it
        #expect(window.shouldAccept(sequenceNumber: 50) == true)
    }

    @Test("isReceived returns false for uninitialized window")
    func testIsReceivedUninitialized() {
        let window = AntiReplayWindow()
        #expect(window.isReceived(sequenceNumber: 0) == false)
        #expect(window.isReceived(sequenceNumber: 100) == false)
    }

    // MARK: - Edge Cases

    @Test("Zero sequence number works")
    func testZeroSequenceNumber() {
        var window = AntiReplayWindow()
        #expect(window.shouldAccept(sequenceNumber: 0) == true)
        #expect(window.shouldAccept(sequenceNumber: 0) == false)
    }

    @Test("Max sequence number works")
    func testMaxSequenceNumber() {
        var window = AntiReplayWindow()
        let maxSeq: UInt64 = 0xFFFF_FFFF_FFFF // 48-bit max
        #expect(window.shouldAccept(sequenceNumber: maxSeq) == true)
        #expect(window.shouldAccept(sequenceNumber: maxSeq) == false)
    }
}
