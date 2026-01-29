/// Secure Random Tests
///
/// Tests the secure random number generation utility that wraps SecRandomCopyBytes.
/// Verifies correct byte counts, entropy (non-repetition), and edge cases.

import Testing
import Foundation
@testable import TLSCore

@Suite("Secure Random Tests")
struct SecureRandomTests {

    // MARK: - Basic Generation

    @Test("Generates requested number of bytes")
    func testGeneratesRequestedBytes() throws {
        let bytes = try secureRandomBytes(count: 32)
        #expect(bytes.count == 32)
    }

    @Test("Generates different values each time")
    func testGeneratesDifferentValues() throws {
        let a = try secureRandomBytes(count: 32)
        let b = try secureRandomBytes(count: 32)
        #expect(a != b)
    }

    @Test("Zero count returns empty data")
    func testZeroCountReturnsEmpty() throws {
        let bytes = try secureRandomBytes(count: 0)
        #expect(bytes.count == 0)
    }

    // MARK: - Various Sizes

    @Test("One byte generation")
    func testOneByteGeneration() throws {
        let bytes = try secureRandomBytes(count: 1)
        #expect(bytes.count == 1)
    }

    @Test("Small allocation (16 bytes)")
    func testSmallAllocation() throws {
        let bytes = try secureRandomBytes(count: 16)
        #expect(bytes.count == 16)
    }

    @Test("Medium allocation (256 bytes)")
    func testMediumAllocation() throws {
        let bytes = try secureRandomBytes(count: 256)
        #expect(bytes.count == 256)
    }

    @Test("Large allocation (64KB)")
    func testLargeAllocation() throws {
        let bytes = try secureRandomBytes(count: 64 * 1024)
        #expect(bytes.count == 64 * 1024)
    }

    // MARK: - Cryptographic Use Cases

    @Test("32-byte client/server random")
    func testClientServerRandom() throws {
        let random = try secureRandomBytes(count: 32)
        #expect(random.count == 32)

        // Verify not all zeros (entropy check)
        let allZeros = Data(repeating: 0x00, count: 32)
        #expect(random != allZeros)
    }

    @Test("12-byte IV generation")
    func testIVGeneration() throws {
        let iv = try secureRandomBytes(count: 12)
        #expect(iv.count == 12)
    }

    @Test("16-byte key generation")
    func testKeyGeneration() throws {
        let key = try secureRandomBytes(count: 16)
        #expect(key.count == 16)

        // Keys should have high entropy (not predictable)
        let allOnes = Data(repeating: 0xFF, count: 16)
        #expect(key != allOnes)
    }

    @Test("32-byte HMAC key generation")
    func testHMACKeyGeneration() throws {
        let key = try secureRandomBytes(count: 32)
        #expect(key.count == 32)
    }

    // MARK: - Statistical Properties

    @Test("Multiple generations are all different")
    func testMultipleGenerationsAreDifferent() throws {
        var seen = Set<Data>()
        for _ in 0..<100 {
            let bytes = try secureRandomBytes(count: 16)
            #expect(!seen.contains(bytes), "Generated duplicate random data")
            seen.insert(bytes)
        }
        #expect(seen.count == 100)
    }

    @Test("Byte distribution has entropy")
    func testByteDistributionHasEntropy() throws {
        // Generate a larger sample
        let bytes = try secureRandomBytes(count: 1000)

        // Count byte values (simple entropy check)
        var counts = [Int](repeating: 0, count: 256)
        for byte in bytes {
            counts[Int(byte)] += 1
        }

        // Check that not all bytes are the same value
        let uniqueValues = counts.filter { $0 > 0 }.count
        #expect(uniqueValues > 100, "Expected good distribution, got \(uniqueValues) unique values")
    }

    // MARK: - Consistency

    @Test("Repeated calls maintain correct count")
    func testRepeatedCallsMaintainCount() throws {
        for size in [1, 8, 16, 32, 64, 128, 256] {
            let bytes = try secureRandomBytes(count: size)
            #expect(bytes.count == size, "Expected \(size) bytes, got \(bytes.count)")
        }
    }

    @Test("Concurrent generation is safe")
    func testConcurrentGeneration() async throws {
        // Generate random bytes concurrently
        await withTaskGroup(of: Data.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    try! secureRandomBytes(count: 32)
                }
            }

            var results = [Data]()
            for await result in group {
                results.append(result)
            }

            // All should be different
            let uniqueCount = Set(results).count
            #expect(uniqueCount == 10, "Expected 10 unique values, got \(uniqueCount)")
        }
    }
}
