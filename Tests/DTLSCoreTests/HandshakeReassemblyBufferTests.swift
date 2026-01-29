/// Handshake Reassembly Buffer Tests (RFC 6347 §4.2.3)
///
/// Tests the fragmented DTLS handshake message reassembly buffer.
/// Verifies correct handling of in-order, out-of-order, duplicate,
/// and invalid fragments.

import Testing
import Foundation
@testable import DTLSCore

@Suite("Handshake Reassembly Buffer Tests")
struct HandshakeReassemblyBufferTests {

    // MARK: - Non-Fragmented Messages

    @Test("Non-fragmented message returns immediately")
    func testNonFragmentedReturnsImmediately() {
        var buffer = HandshakeReassemblyBuffer()
        let header = DTLSHandshakeHeader(
            messageType: .clientHello,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 10
        )
        let body = Data(repeating: 0xAA, count: 10)

        let result = buffer.addFragment(header: header, body: body)
        #expect(result != nil)
        #expect(buffer.pendingCount == 0)
    }

    @Test("Non-fragmented with zero-length body")
    func testNonFragmentedZeroLength() {
        var buffer = HandshakeReassemblyBuffer()
        let header = DTLSHandshakeHeader(
            messageType: .finished,
            length: 0,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 0
        )
        let body = Data()

        let result = buffer.addFragment(header: header, body: body)
        #expect(result != nil)
    }

    // MARK: - In-Order Fragments

    @Test("In-order fragments reassemble correctly")
    func testInOrderFragments() {
        var buffer = HandshakeReassemblyBuffer()

        // Fragment 1: bytes 0-4
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        let b1 = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        #expect(buffer.addFragment(header: h1, body: b1) == nil)
        #expect(buffer.pendingCount == 1)

        // Fragment 2: bytes 5-9
        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 5,
            fragmentLength: 5
        )
        let b2 = Data([0x05, 0x06, 0x07, 0x08, 0x09])
        let result = buffer.addFragment(header: h2, body: b2)

        #expect(result != nil)
        #expect(buffer.pendingCount == 0)

        // Verify reassembled content
        if let result = result {
            // Skip 12-byte header, check body
            let body = result.suffix(from: 12)
            #expect(body == Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]))
        }
    }

    @Test("Three fragments in order")
    func testThreeFragmentsInOrder() {
        var buffer = HandshakeReassemblyBuffer()

        // Fragment 1
        let h1 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange,
            length: 15,
            messageSeq: 1,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        #expect(buffer.addFragment(header: h1, body: Data([0x00, 0x01, 0x02, 0x03, 0x04])) == nil)

        // Fragment 2
        let h2 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange,
            length: 15,
            messageSeq: 1,
            fragmentOffset: 5,
            fragmentLength: 5
        )
        #expect(buffer.addFragment(header: h2, body: Data([0x05, 0x06, 0x07, 0x08, 0x09])) == nil)

        // Fragment 3 completes
        let h3 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange,
            length: 15,
            messageSeq: 1,
            fragmentOffset: 10,
            fragmentLength: 5
        )
        let result = buffer.addFragment(header: h3, body: Data([0x0A, 0x0B, 0x0C, 0x0D, 0x0E]))
        #expect(result != nil)
        #expect(buffer.pendingCount == 0)
    }

    // MARK: - Out-of-Order Fragments

    @Test("Out-of-order fragments reassemble correctly")
    func testOutOfOrderFragments() {
        var buffer = HandshakeReassemblyBuffer()

        // Fragment 2 arrives first
        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 5,
            fragmentLength: 5
        )
        let b2 = Data([0x05, 0x06, 0x07, 0x08, 0x09])
        #expect(buffer.addFragment(header: h2, body: b2) == nil)

        // Fragment 1 arrives later
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        let b1 = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        let result = buffer.addFragment(header: h1, body: b1)

        #expect(result != nil)
        #expect(buffer.pendingCount == 0)
    }

    @Test("Reverse order fragments")
    func testReverseOrderFragments() {
        var buffer = HandshakeReassemblyBuffer()

        // Fragment 3 (last)
        let h3 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 9,
            messageSeq: 0,
            fragmentOffset: 6,
            fragmentLength: 3
        )
        #expect(buffer.addFragment(header: h3, body: Data([0x06, 0x07, 0x08])) == nil)

        // Fragment 2 (middle)
        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 9,
            messageSeq: 0,
            fragmentOffset: 3,
            fragmentLength: 3
        )
        #expect(buffer.addFragment(header: h2, body: Data([0x03, 0x04, 0x05])) == nil)

        // Fragment 1 (first) completes
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 9,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 3
        )
        let result = buffer.addFragment(header: h1, body: Data([0x00, 0x01, 0x02]))
        #expect(result != nil)
    }

    // MARK: - Duplicate Fragments

    @Test("Duplicate fragments are handled gracefully")
    func testDuplicateFragments() {
        var buffer = HandshakeReassemblyBuffer()

        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        let b1 = Data([0x00, 0x01, 0x02, 0x03, 0x04])

        // Add same fragment multiple times
        _ = buffer.addFragment(header: h1, body: b1)
        _ = buffer.addFragment(header: h1, body: b1)
        _ = buffer.addFragment(header: h1, body: b1)

        #expect(buffer.pendingCount == 1)

        // Complete with second fragment
        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 5,
            fragmentLength: 5
        )
        let b2 = Data([0x05, 0x06, 0x07, 0x08, 0x09])
        let result = buffer.addFragment(header: h2, body: b2)

        #expect(result != nil)
        #expect(buffer.pendingCount == 0)
    }

    // MARK: - Overlapping Fragments

    @Test("Overlapping fragments are handled")
    func testOverlappingFragments() {
        var buffer = HandshakeReassemblyBuffer()

        // Fragment covering bytes 0-5
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 6
        )
        _ = buffer.addFragment(header: h1, body: Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]))

        // Fragment covering bytes 4-9 (overlaps at 4-5)
        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 4,
            fragmentLength: 6
        )
        let result = buffer.addFragment(header: h2, body: Data([0x04, 0x05, 0x06, 0x07, 0x08, 0x09]))

        #expect(result != nil)
    }

    // MARK: - Boundary Validation

    @Test("Fragment exceeding total length is rejected")
    func testFragmentExceedingLengthRejected() {
        var buffer = HandshakeReassemblyBuffer()

        let header = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 8,
            fragmentLength: 5 // 8+5=13 > 10
        )
        let body = Data(repeating: 0x00, count: 5)

        let result = buffer.addFragment(header: header, body: body)
        #expect(result == nil)
        #expect(buffer.pendingCount == 0)
    }

    @Test("Body size mismatch is rejected")
    func testBodySizeMismatchRejected() {
        var buffer = HandshakeReassemblyBuffer()

        let header = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        let body = Data(repeating: 0x00, count: 3) // 5 != 3

        let result = buffer.addFragment(header: header, body: body)
        #expect(result == nil)
    }

    @Test("Fragment offset at boundary is valid")
    func testFragmentOffsetAtBoundary() {
        var buffer = HandshakeReassemblyBuffer()

        // Fragment exactly at the end boundary
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 5,
            fragmentLength: 5 // 5+5=10, exactly at length
        )
        _ = buffer.addFragment(header: h1, body: Data(repeating: 0xBB, count: 5))

        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        let result = buffer.addFragment(header: h2, body: Data(repeating: 0xAA, count: 5))

        #expect(result != nil)
    }

    @Test("Fragment offset beyond length is rejected")
    func testFragmentOffsetBeyondLength() {
        var buffer = HandshakeReassemblyBuffer()

        let header = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 11, // Beyond total length
            fragmentLength: 1
        )
        let body = Data([0x00])

        let result = buffer.addFragment(header: header, body: body)
        #expect(result == nil)
    }

    // MARK: - Inconsistent Fragment Validation

    @Test("Inconsistent message type is rejected")
    func testInconsistentMessageTypeRejected() {
        var buffer = HandshakeReassemblyBuffer()

        // First fragment as certificate
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        _ = buffer.addFragment(header: h1, body: Data(repeating: 0xAA, count: 5))

        // Second fragment with different type
        let h2 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange, // Different type!
            length: 10,
            messageSeq: 0,
            fragmentOffset: 5,
            fragmentLength: 5
        )
        let result = buffer.addFragment(header: h2, body: Data(repeating: 0xBB, count: 5))

        #expect(result == nil)
    }

    @Test("Inconsistent total length is rejected")
    func testInconsistentTotalLengthRejected() {
        var buffer = HandshakeReassemblyBuffer()

        // First fragment with length 10
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        _ = buffer.addFragment(header: h1, body: Data(repeating: 0xAA, count: 5))

        // Second fragment with different total length
        let h2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 20, // Different total length!
            messageSeq: 0,
            fragmentOffset: 5,
            fragmentLength: 5
        )
        let result = buffer.addFragment(header: h2, body: Data(repeating: 0xBB, count: 5))

        #expect(result == nil)
    }

    // MARK: - Multiple Messages

    @Test("Multiple messages tracked independently")
    func testMultipleMessages() {
        var buffer = HandshakeReassemblyBuffer()

        // Message 0, Fragment 1
        let h0_1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 6,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 3
        )
        _ = buffer.addFragment(header: h0_1, body: Data([0x00, 0x01, 0x02]))

        // Message 1, Fragment 1
        let h1_1 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange,
            length: 4,
            messageSeq: 1,
            fragmentOffset: 0,
            fragmentLength: 2
        )
        _ = buffer.addFragment(header: h1_1, body: Data([0x10, 0x11]))

        #expect(buffer.pendingCount == 2)

        // Complete Message 1
        let h1_2 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange,
            length: 4,
            messageSeq: 1,
            fragmentOffset: 2,
            fragmentLength: 2
        )
        let result1 = buffer.addFragment(header: h1_2, body: Data([0x12, 0x13]))
        #expect(result1 != nil)
        #expect(buffer.pendingCount == 1)

        // Complete Message 0
        let h0_2 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 6,
            messageSeq: 0,
            fragmentOffset: 3,
            fragmentLength: 3
        )
        let result0 = buffer.addFragment(header: h0_2, body: Data([0x03, 0x04, 0x05]))
        #expect(result0 != nil)
        #expect(buffer.pendingCount == 0)
    }

    // MARK: - Clear

    @Test("Clear removes all pending messages")
    func testClearRemovesPending() {
        var buffer = HandshakeReassemblyBuffer()

        // Add partial fragments
        let h1 = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 10,
            messageSeq: 0,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        _ = buffer.addFragment(header: h1, body: Data(repeating: 0xAA, count: 5))

        let h2 = DTLSHandshakeHeader(
            messageType: .serverKeyExchange,
            length: 10,
            messageSeq: 1,
            fragmentOffset: 0,
            fragmentLength: 5
        )
        _ = buffer.addFragment(header: h2, body: Data(repeating: 0xBB, count: 5))

        #expect(buffer.pendingCount == 2)

        buffer.clear()

        #expect(buffer.pendingCount == 0)
    }

    // MARK: - Header Encoding

    @Test("Reassembled message has correct header")
    func testReassembledMessageHeader() {
        var buffer = HandshakeReassemblyBuffer()

        let h1 = DTLSHandshakeHeader(
            messageType: .clientKeyExchange,
            length: 4,
            messageSeq: 5,
            fragmentOffset: 0,
            fragmentLength: 2
        )
        _ = buffer.addFragment(header: h1, body: Data([0xAA, 0xBB]))

        let h2 = DTLSHandshakeHeader(
            messageType: .clientKeyExchange,
            length: 4,
            messageSeq: 5,
            fragmentOffset: 2,
            fragmentLength: 2
        )
        let result = buffer.addFragment(header: h2, body: Data([0xCC, 0xDD]))

        #expect(result != nil)
        if let result = result {
            // Verify header fields
            #expect(result[0] == DTLSHandshakeType.clientKeyExchange.rawValue)

            // Length (3 bytes): 4
            #expect(result[1] == 0x00)
            #expect(result[2] == 0x00)
            #expect(result[3] == 0x04)

            // Message seq (2 bytes): 5
            #expect(result[4] == 0x00)
            #expect(result[5] == 0x05)

            // Fragment offset (3 bytes): 0
            #expect(result[6] == 0x00)
            #expect(result[7] == 0x00)
            #expect(result[8] == 0x00)

            // Fragment length (3 bytes): 4
            #expect(result[9] == 0x00)
            #expect(result[10] == 0x00)
            #expect(result[11] == 0x04)

            // Body
            #expect(result[12] == 0xAA)
            #expect(result[13] == 0xBB)
            #expect(result[14] == 0xCC)
            #expect(result[15] == 0xDD)
        }
    }
}
