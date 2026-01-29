/// DTLS Record Layer Replay Tests (RFC 6347 §4.1.2.6)
///
/// Integration tests for replay protection at the record layer level.
/// Verifies that the anti-replay window properly rejects duplicate and
/// out-of-window sequence numbers.

import Testing
import Foundation
import Crypto
@testable import DTLSRecord
@testable import DTLSCore

@Suite("DTLS Record Layer Replay Tests")
struct DTLSRecordLayerReplayTests {

    // MARK: - Helpers

    private static func makeTestKeys() -> (key: SymmetricKey, fixedIV: Data) {
        let key = SymmetricKey(data: Data(repeating: 0xAB, count: 16))
        let iv = Data(repeating: 0xCD, count: 4)
        return (key, iv)
    }

    /// Creates a pair of connected record layers (writer encrypts, reader decrypts)
    private static func makeConnectedLayers() -> (writer: DTLSRecordLayer, reader: DTLSRecordLayer) {
        let writer = DTLSRecordLayer()
        let reader = DTLSRecordLayer()
        let (key, iv) = makeTestKeys()

        writer.setWriteKeys(key: key, fixedIV: iv)
        reader.setReadKeys(key: key, fixedIV: iv)

        return (writer, reader)
    }

    /// Extract record from decode result, or nil if not a record
    private static func extractRecord(_ result: RecordDecodeResult) -> DTLSRecord? {
        if case .record(let r, _) = result { return r }
        return nil
    }

    /// Check if result is a valid record
    private static func isRecord(_ result: RecordDecodeResult) -> Bool {
        if case .record = result { return true }
        return false
    }

    /// Check if result is discarded (replayed or too old)
    private static func isDiscarded(_ result: RecordDecodeResult) -> Bool {
        if case .discarded = result { return true }
        return false
    }

    // MARK: - Basic Replay Protection

    @Test("First encrypted record is accepted")
    func testFirstEncryptedRecordAccepted() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        let record = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x01, 0x02, 0x03])
        )

        let result = try reader.decodeRecord(from: record)
        #expect(Self.isRecord(result))
        #expect(Self.extractRecord(result)?.fragment == Data([0x01, 0x02, 0x03]))
    }

    @Test("Replayed encrypted record is discarded")
    func testReplayedRecordDiscarded() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        let record = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x01, 0x02, 0x03])
        )

        // First reception: success
        let result1 = try reader.decodeRecord(from: record)
        #expect(Self.isRecord(result1))

        // Second reception (replay): silently discarded
        let result2 = try reader.decodeRecord(from: record)
        #expect(Self.isDiscarded(result2), "Replayed record should be silently discarded")
    }

    @Test("Multiple unique records all accepted")
    func testMultipleUniqueRecordsAccepted() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        var results: [Data] = []
        for i in 0..<10 {
            let record = try writer.encodeRecord(
                contentType: .applicationData,
                plaintext: Data([UInt8(i)])
            )
            let result = try reader.decodeRecord(from: record)
            #expect(Self.isRecord(result), "Record \(i) should be accepted")
            if let decoded = Self.extractRecord(result) {
                results.append(decoded.fragment)
            }
        }

        #expect(results.count == 10)
    }

    // MARK: - Out-of-Order Handling

    @Test("Out-of-order records within window are accepted")
    func testOutOfOrderWithinWindowAccepted() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        // Encode records in order
        var encodedRecords: [Data] = []
        for i in 0..<5 {
            let record = try writer.encodeRecord(
                contentType: .applicationData,
                plaintext: Data([UInt8(i)])
            )
            encodedRecords.append(record)
        }

        // Process in reverse order (simulating network reordering)
        for i in stride(from: 4, through: 0, by: -1) {
            let result = try reader.decodeRecord(from: encodedRecords[i])
            #expect(Self.isRecord(result), "Out-of-order record \(i) should be accepted")
        }
    }

    @Test("Same sequence number rejected after out-of-order processing")
    func testSameSequenceRejectedAfterOutOfOrder() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        let record0 = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x00])
        )
        let record1 = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x01])
        )
        let record2 = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x02])
        )

        // Process: 2, 0, 1 (out of order)
        #expect(Self.isRecord(try reader.decodeRecord(from: record2)))
        #expect(Self.isRecord(try reader.decodeRecord(from: record0)))
        #expect(Self.isRecord(try reader.decodeRecord(from: record1)))

        // Replay any of them - should fail
        #expect(Self.isDiscarded(try reader.decodeRecord(from: record0)))
        #expect(Self.isDiscarded(try reader.decodeRecord(from: record1)))
        #expect(Self.isDiscarded(try reader.decodeRecord(from: record2)))
    }

    // MARK: - Window Boundary

    @Test("Record outside window is rejected")
    func testRecordOutsideWindowRejected() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        // Encode first record
        let earlyRecord = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x00])
        )

        // Send 70 more records to move the window forward
        // (window size is 64, so after 70 records, first should be outside)
        for i in 1...70 {
            let record = try writer.encodeRecord(
                contentType: .applicationData,
                plaintext: Data([UInt8(i % 256)])
            )
            _ = try reader.decodeRecord(from: record)
        }

        // Now try to process the early record - should be rejected as too old
        let result = try reader.decodeRecord(from: earlyRecord)
        #expect(Self.isDiscarded(result), "Record outside window should be rejected")
    }

    @Test("Record at window boundary is accepted")
    func testRecordAtWindowBoundaryAccepted() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        // Encode records 0 through 63
        var records: [Data] = []
        for i in 0..<64 {
            let record = try writer.encodeRecord(
                contentType: .applicationData,
                plaintext: Data([UInt8(i)])
            )
            records.append(record)
        }

        // Process only record 63 (sets highest to 63)
        _ = try reader.decodeRecord(from: records[63])

        // Record 0 should still be within window (63 - 0 = 63 < 64)
        let result = try reader.decodeRecord(from: records[0])
        #expect(Self.isRecord(result), "Record at window boundary should be accepted")
    }

    // MARK: - Epoch Transitions

    @Test("Replay window resets on epoch change")
    func testReplayWindowResetsOnEpochChange() throws {
        let writer = DTLSRecordLayer()
        let reader = DTLSRecordLayer()
        let (key, iv) = Self.makeTestKeys()

        // Epoch 1
        writer.setWriteKeys(key: key, fixedIV: iv)
        reader.setReadKeys(key: key, fixedIV: iv)

        let record1 = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x01])
        )
        _ = try reader.decodeRecord(from: record1)

        // Epoch 2 - new keys
        let key2 = SymmetricKey(data: Data(repeating: 0xEF, count: 16))
        let iv2 = Data(repeating: 0x12, count: 4)
        writer.setWriteKeys(key: key2, fixedIV: iv2)
        reader.setReadKeys(key: key2, fixedIV: iv2)

        // Sequence number 0 at new epoch should be accepted
        let record2 = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x02])
        )
        let result = try reader.decodeRecord(from: record2)
        #expect(Self.isRecord(result), "First record at new epoch should be accepted")
    }

    // MARK: - Decryption Failure Does Not Mark Sequence

    @Test("Decryption failure does not mark sequence as used")
    func testDecryptionFailureDoesNotMarkSequence() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        // Create a valid record
        let validRecord = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x01, 0x02, 0x03])
        )

        // Create a tampered record by modifying the ciphertext
        var tamperedRecord = validRecord
        // Modify a byte in the encrypted portion (after header)
        if tamperedRecord.count > 20 {
            tamperedRecord[tamperedRecord.count - 5] ^= 0xFF
        }

        // Tampered record should fail decryption
        #expect(throws: (any Error).self) {
            _ = try reader.decodeRecord(from: tamperedRecord)
        }

        // Valid record should still be accepted
        // (sequence number was not marked because decryption failed)
        let result = try reader.decodeRecord(from: validRecord)
        #expect(Self.isRecord(result), "Valid record should be accepted after tampered record failed")
    }

    // MARK: - Plaintext Records (Epoch 0)

    @Test("Plaintext records at epoch 0 bypass replay protection")
    func testPlaintextRecordsBypassReplayProtection() throws {
        let layer = DTLSRecordLayer()

        let record = try layer.encodeRecord(
            contentType: .handshake,
            plaintext: Data([0x01, 0x02])
        )

        // Both should succeed - epoch 0 records don't use replay protection
        let result1 = try layer.decodeRecord(from: record)
        #expect(Self.isRecord(result1))

        let result2 = try layer.decodeRecord(from: record)
        #expect(Self.isRecord(result2), "Plaintext records should not be subject to replay protection")
    }

    // MARK: - Stress Test

    @Test("Replay protection handles many sequential records")
    func testReplayProtectionHandlesManyRecords() throws {
        let (writer, reader) = Self.makeConnectedLayers()

        // Send 200 records
        var records: [Data] = []
        for i in 0..<200 {
            let record = try writer.encodeRecord(
                contentType: .applicationData,
                plaintext: Data([UInt8(i % 256)])
            )
            records.append(record)
            let result = try reader.decodeRecord(from: record)
            #expect(Self.isRecord(result), "Record \(i) should be accepted")
        }

        // Try to replay recent records - all should fail
        for i in 140..<200 {
            let result = try reader.decodeRecord(from: records[i])
            #expect(Self.isDiscarded(result), "Replay of record \(i) should be rejected")
        }

        // Old records (outside window) should also be rejected
        for i in 0..<100 {
            let result = try reader.decodeRecord(from: records[i])
            #expect(Self.isDiscarded(result), "Old record \(i) should be rejected")
        }
    }
}
