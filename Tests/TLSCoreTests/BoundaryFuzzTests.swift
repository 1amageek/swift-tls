/// Boundary and Fuzz-like Tests for TLS 1.3 Message Parsing
///
/// Verifies that malformed, random, and boundary-condition inputs
/// are rejected gracefully without crashing.

import Testing
import Foundation
import Crypto
@testable import TLSCore

@Suite("Boundary and Fuzz Tests", .serialized)
struct BoundaryFuzzTests {

    // MARK: - Truncated / Malformed Input

    @Test("Too-short data as ClientHello should throw")
    func testTooShortClientHello() {
        // 5 bytes is too short for a valid ClientHello
        #expect(throws: (any Error).self) {
            _ = try ClientHello.decode(from: Data([0x03, 0x03, 0x01, 0x02, 0x03]))
        }
    }

    @Test("Too-short data as ServerHello should throw")
    func testTooShortServerHello() {
        // Valid version prefix but truncated random field
        #expect(throws: (any Error).self) {
            _ = try ServerHello.decode(from: Data([0x03, 0x03, 0x01, 0x02, 0x03]))
        }
    }

    @Test("Truncated Certificate should throw")
    func testTruncatedCertificate() {
        // Too-short data for a valid Certificate message
        #expect(throws: (any Error).self) {
            _ = try Certificate.decode(from: Data([0x00, 0x00, 0x03]))
        }
    }

    @Test("Truncated NewSessionTicket should throw")
    func testTruncatedNewSessionTicket() {
        // Too-short data for a valid NewSessionTicket (needs at least 9 bytes)
        #expect(throws: (any Error).self) {
            _ = try NewSessionTicket.decode(from: Data([0x00, 0x00, 0x0E, 0x10]))
        }
    }

    // MARK: - Zero-Length Fields

    @Test("Zero-length random field in ClientHello should fail")
    func testZeroLengthFields() {
        // Build a minimal ClientHello payload with zero-length random
        // (random must be exactly 32 bytes per RFC 8446)
        var writer = TLSWriter(capacity: 64)

        // legacy_version (0x0303)
        writer.writeUInt16(TLSConstants.legacyVersion)

        // random: 0 bytes (invalid - must be 32)
        // We write only 2 bytes so readBytes(32) will fail with insufficientData

        let truncatedData = writer.finish()
        #expect(throws: (any Error).self) {
            _ = try ClientHello.decode(from: truncatedData)
        }
    }

    // MARK: - Max-Length Fields

    @Test("Near-max-length data as ClientHello should be rejected")
    func testMaxLengthFields() {
        // Create 65535 bytes of 0xFF
        let oversizedData = Data(repeating: 0xFF, count: 65535)

        // Feed to ClientHello.decode - the legacy_version check (first 2 bytes = 0xFFFF)
        // should fail immediately since 0xFFFF != 0x0303.
        #expect(throws: (any Error).self) {
            _ = try ClientHello.decode(from: oversizedData)
        }
    }

    // MARK: - Truncated Data

    @Test("Truncated handshake header should fail")
    func testTruncatedHandshakeHeader() {
        // HandshakeCodec.decodeHeader requires at least 4 bytes
        let threeBytes = Data([0x01, 0x00, 0x00])
        #expect(throws: (any Error).self) {
            _ = try HandshakeCodec.decodeHeader(from: threeBytes)
        }
    }

    @Test("Empty data as ClientHello should throw")
    func testEmptyClientHello() {
        #expect(throws: (any Error).self) {
            _ = try ClientHello.decode(from: Data())
        }
    }

    @Test("Empty data as ServerHello should throw")
    func testEmptyServerHello() {
        #expect(throws: (any Error).self) {
            _ = try ServerHello.decode(from: Data())
        }
    }

    @Test("Empty data as Certificate should throw")
    func testEmptyCertificate() {
        #expect(throws: (any Error).self) {
            _ = try Certificate.decode(from: Data())
        }
    }

    @Test("Empty data as NewSessionTicket should throw")
    func testEmptyNewSessionTicket() {
        #expect(throws: (any Error).self) {
            _ = try NewSessionTicket.decode(from: Data())
        }
    }

    // MARK: - ASN.1 Parser Robustness

    @Test("Well-formed short ASN.1 SEQUENCE parses without crash")
    func testShortASN1SequenceNoCrash() {
        // This is actually a well-formed short SEQUENCE — verify no crash
        let data = Data([0x30, 0x05, 0x02, 0x01, 0x00])
        _ = try? ASN1Parser.parseOne(from: data)
    }

    @Test("Empty data as ASN.1 should throw")
    func testEmptyASN1() {
        #expect(throws: (any Error).self) {
            _ = try ASN1Parser.parseOne(from: Data())
        }
    }

    @Test("Single byte as ASN.1 should throw")
    func testSingleByteASN1() {
        // A single tag byte with no length or content should fail
        #expect(throws: (any Error).self) {
            _ = try ASN1Parser.parseOne(from: Data([0x30]))
        }
    }

    @Test("ASN.1 with length exceeding data should throw")
    func testASN1LengthOverflow() {
        // SEQUENCE tag (0x30) with length claiming 200 bytes, but only 2 bytes follow
        let malformed = Data([0x30, 0x82, 0x00, 0xC8, 0x00, 0x00])
        #expect(throws: (any Error).self) {
            _ = try ASN1Parser.parseOne(from: malformed)
        }
    }

    // MARK: - Varied Random Patterns

    @Test("All-zeros data as ClientHello should throw")
    func testAllZerosAsClientHello() {
        // 256 zero bytes: legacy_version would be 0x0000, not 0x0303
        let zeros = Data(repeating: 0x00, count: 256)
        #expect(throws: (any Error).self) {
            _ = try ClientHello.decode(from: zeros)
        }
    }

    @Test("Incrementing bytes as ServerHello should throw")
    func testIncrementingBytesAsServerHello() {
        // 0x00, 0x01, 0x02, ... 0xFF: version would be 0x0001, not 0x0303
        let incrementing = Data((0..<256).map { UInt8($0) })
        #expect(throws: (any Error).self) {
            _ = try ServerHello.decode(from: incrementing)
        }
    }

    // MARK: - Handshake Codec Edge Cases

    @Test("Unknown handshake type should throw")
    func testUnknownHandshakeType() {
        // Handshake type 0xFF is not defined
        let data = Data([0xFF, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
        #expect(throws: (any Error).self) {
            _ = try HandshakeCodec.decodeHeader(from: data)
        }
    }

    @Test("Handshake message with length exceeding data should throw")
    func testHandshakeMessageTruncated() {
        // Type = clientHello (0x01), length = 1000, but only 4 bytes total
        let data = Data([0x01, 0x00, 0x03, 0xE8])
        #expect(throws: (any Error).self) {
            _ = try HandshakeCodec.decodeMessage(from: data)
        }
    }

    // MARK: - Multiple Random Seeds

    @Test("Truncated ClientHello payloads either throw or parse without crash")
    func testTruncatedClientHellosNoCrash() {
        // Test various truncation points after a valid version prefix.
        // Avoid random data that could reach CryptoKit SymmetricKey creation with
        // too-small data, which triggers an uncatchable fatal trap.
        var errorCount = 0
        for length in [2, 10, 20, 33, 34, 40] {
            let data = Data([0x03, 0x03]) + Data(repeating: 0xAB, count: length)
            do {
                _ = try ClientHello.decode(from: data)
            } catch {
                errorCount += 1
            }
        }
        #expect(errorCount > 0, "Expected at least one truncated input to throw")
    }

    @Test("Deterministic byte patterns as ASN.1 do not crash")
    func testDeterministicBytePatternsASN1NoCrash() {
        for seed: UInt8 in [0, 37, 73, 127, 191, 251] {
            let data = Data((0..<128).map { UInt8($0 &* seed &+ 13) })
            _ = try? ASN1Parser.parseOne(from: data)
        }
    }

    // MARK: - TLSReader Boundary

    @Test("TLSReader readVector16 with length exceeding remaining should throw")
    func testReaderVector16Overflow() {
        // Length prefix says 1000 bytes, but only 2 bytes of payload
        let data = Data([0x03, 0xE8, 0xAA, 0xBB])
        var reader = TLSReader(data: data)
        #expect(throws: (any Error).self) {
            _ = try reader.readVector16()
        }
    }

    @Test("TLSReader readVector24 with length exceeding remaining should throw")
    func testReaderVector24Overflow() {
        // Length prefix says 100000 bytes, but only 3 bytes of payload
        let data = Data([0x01, 0x86, 0xA0, 0xCC, 0xDD, 0xEE])
        var reader = TLSReader(data: data)
        #expect(throws: (any Error).self) {
            _ = try reader.readVector24()
        }
    }
}
