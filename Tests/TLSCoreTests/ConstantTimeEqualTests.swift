/// Constant-Time Equal Tests
///
/// Tests the constant-time comparison function used for verify_data,
/// HMAC tags, and cookie verification to prevent timing attacks.

import Testing
import Foundation
@testable import TLSCore

@Suite("Constant-Time Equal Tests")
struct ConstantTimeEqualTests {

    // MARK: - Correctness Tests

    @Test("Equal data returns true")
    func testEqualDataReturnsTrue() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("Different data returns false")
    func testDifferentDataReturnsFalse() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x05])
        #expect(constantTimeEqual(a, b) == false)
    }

    @Test("Different lengths return false")
    func testDifferentLengthsReturnFalse() {
        let a = Data([0x01, 0x02, 0x03])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        #expect(constantTimeEqual(a, b) == false)
    }

    @Test("Empty data is equal")
    func testEmptyDataEqual() {
        let a = Data()
        let b = Data()
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("Empty vs non-empty returns false")
    func testEmptyVsNonEmpty() {
        let a = Data()
        let b = Data([0x01])
        #expect(constantTimeEqual(a, b) == false)
    }

    // MARK: - Difference Position Tests

    @Test("First byte difference detected")
    func testFirstByteDifferent() {
        let a = Data([0xFF, 0x02, 0x03, 0x04])
        let b = Data([0x00, 0x02, 0x03, 0x04])
        #expect(constantTimeEqual(a, b) == false)
    }

    @Test("Middle byte difference detected")
    func testMiddleByteDifferent() {
        let a = Data([0x01, 0x02, 0xFF, 0x04])
        let b = Data([0x01, 0x02, 0x00, 0x04])
        #expect(constantTimeEqual(a, b) == false)
    }

    @Test("Last byte difference detected")
    func testLastByteDifferent() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0xFF])
        #expect(constantTimeEqual(a, b) == false)
    }

    @Test("Single bit difference detected")
    func testSingleBitDifference() {
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x05]) // 0x04 vs 0x05 = 1 bit diff
        #expect(constantTimeEqual(a, b) == false)
    }

    // MARK: - Cryptographic Sizes

    @Test("32-byte verify_data comparison")
    func testVerifyDataSize() {
        let a = Data(repeating: 0xAA, count: 32)
        var b = Data(repeating: 0xAA, count: 32)
        #expect(constantTimeEqual(a, b) == true)

        b[31] = 0xBB // Change last byte
        #expect(constantTimeEqual(a, b) == false)
    }

    @Test("48-byte SHA-384 hash comparison")
    func testSHA384Size() {
        let a = Data(repeating: 0x55, count: 48)
        let b = Data(repeating: 0x55, count: 48)
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("256-byte HMAC comparison")
    func testLargeSize() {
        let a = Data(repeating: 0x55, count: 256)
        var b = Data(repeating: 0x55, count: 256)
        #expect(constantTimeEqual(a, b) == true)

        b[0] = 0x00 // Change first byte
        #expect(constantTimeEqual(a, b) == false)

        b[0] = 0x55
        b[255] = 0x00 // Change last byte
        #expect(constantTimeEqual(a, b) == false)
    }

    // MARK: - Data Index Handling

    @Test("Subdata comparison works correctly")
    func testSubdataComparison() {
        let full = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        let a = full.subdata(in: 1..<4) // [0x01, 0x02, 0x03]
        let b = Data([0x01, 0x02, 0x03])
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("Subdata with non-zero startIndex")
    func testSubdataWithNonZeroStartIndex() {
        let full1 = Data([0xFF, 0xFF, 0x01, 0x02, 0x03])
        let full2 = Data([0xAA, 0x01, 0x02, 0x03])

        let a = full1.subdata(in: 2..<5) // [0x01, 0x02, 0x03]
        let b = full2.subdata(in: 1..<4) // [0x01, 0x02, 0x03]

        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("Suffix comparison")
    func testSuffixComparison() {
        let full = Data([0x00, 0x01, 0x02, 0x03, 0x04])
        let a = full.suffix(3) // [0x02, 0x03, 0x04]
        let b = Data([0x02, 0x03, 0x04])
        #expect(constantTimeEqual(Data(a), b) == true)
    }

    // MARK: - All Zeros / All Ones

    @Test("All zeros comparison")
    func testAllZeros() {
        let a = Data(repeating: 0x00, count: 32)
        let b = Data(repeating: 0x00, count: 32)
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("All ones comparison")
    func testAllOnes() {
        let a = Data(repeating: 0xFF, count: 32)
        let b = Data(repeating: 0xFF, count: 32)
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("Zeros vs ones")
    func testZerosVsOnes() {
        let a = Data(repeating: 0x00, count: 32)
        let b = Data(repeating: 0xFF, count: 32)
        #expect(constantTimeEqual(a, b) == false)
    }

    // MARK: - Pattern Tests

    @Test("Alternating pattern equal")
    func testAlternatingPatternEqual() {
        var a = Data(count: 32)
        var b = Data(count: 32)
        for i in 0..<32 {
            a[i] = UInt8(i % 2 == 0 ? 0xAA : 0x55)
            b[i] = UInt8(i % 2 == 0 ? 0xAA : 0x55)
        }
        #expect(constantTimeEqual(a, b) == true)
    }

    @Test("Incrementing pattern equal")
    func testIncrementingPatternEqual() {
        var a = Data(count: 256)
        var b = Data(count: 256)
        for i in 0..<256 {
            a[i] = UInt8(i)
            b[i] = UInt8(i)
        }
        #expect(constantTimeEqual(a, b) == true)
    }
}
