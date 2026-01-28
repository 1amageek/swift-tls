/// DTLSRecordLayer Contract Tests
///
/// Tests the encryption boundary invariants:
/// A. Records before key installation are plaintext at epoch 0
/// B. Key installation advances epochs correctly
/// C. Encrypted records can only be produced after key installation
/// D. Sequence numbers reset after epoch change

import Testing
import Foundation
import Crypto
@testable import DTLSRecord
@testable import DTLSCore

@Suite("DTLSRecordLayer Contract Tests")
struct DTLSRecordLayerContractTests {

    // MARK: - Helpers

    private static func makeTestKeys() -> (key: SymmetricKey, fixedIV: Data) {
        let key = SymmetricKey(data: Data(repeating: 0xAB, count: 16))
        let iv = Data(repeating: 0xCD, count: 4)
        return (key, iv)
    }

    private static func makeAlternateKeys() -> (key: SymmetricKey, fixedIV: Data) {
        let key = SymmetricKey(data: Data(repeating: 0xEF, count: 16))
        let iv = Data(repeating: 0x12, count: 4)
        return (key, iv)
    }

    // MARK: - Contract A: Plaintext at Epoch 0

    @Test("Records before key installation are plaintext at epoch 0")
    func recordsBeforeKeyInstallationArePlaintext() throws {
        let layer = DTLSRecordLayer()
        let plaintext = Data("hello plaintext".utf8)

        let encoded = try layer.encodeRecord(
            contentType: .handshake,
            plaintext: plaintext
        )

        // Decode the raw record to inspect epoch and fragment
        guard let (record, _) = try DTLSRecord.decode(from: encoded) else {
            Issue.record("Failed to decode record")
            return
        }

        #expect(record.epoch == 0)
        #expect(record.fragment == plaintext, "Fragment should equal plaintext (no encryption)")
    }

    @Test("Sequence number increments within epoch")
    func sequenceNumberIncrementsWithinEpoch() throws {
        let layer = DTLSRecordLayer()

        var records: [DTLSRecord] = []
        for _ in 0..<3 {
            let encoded = try layer.encodeRecord(
                contentType: .handshake,
                plaintext: Data([0x00])
            )
            guard let (record, _) = try DTLSRecord.decode(from: encoded) else {
                Issue.record("Failed to decode record")
                return
            }
            records.append(record)
        }

        #expect(records[0].sequenceNumber == 0)
        #expect(records[1].sequenceNumber == 1)
        #expect(records[2].sequenceNumber == 2)
        for record in records {
            #expect(record.epoch == 0)
        }
    }

    // MARK: - Contract B: Epoch Advancement

    @Test("setWriteKeys advances write epoch")
    func setWriteKeysAdvancesWriteEpoch() throws {
        let layer = DTLSRecordLayer()
        #expect(layer.writeEpoch == 0)

        let (key, iv) = Self.makeTestKeys()
        layer.setWriteKeys(key: key, fixedIV: iv)

        #expect(layer.writeEpoch == 1)

        // Encoded record should have epoch 1
        let encoded = try layer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x42])
        )
        guard let (record, _) = try DTLSRecord.decode(from: encoded) else {
            Issue.record("Failed to decode record")
            return
        }
        #expect(record.epoch == 1)
    }

    @Test("setReadKeys advances read epoch")
    func setReadKeysAdvancesReadEpoch() {
        let layer = DTLSRecordLayer()
        #expect(layer.readEpoch == 0)

        let (key, iv) = Self.makeTestKeys()
        layer.setReadKeys(key: key, fixedIV: iv)

        #expect(layer.readEpoch == 1)
    }

    @Test("Write epoch and read epoch are independent")
    func writeEpochAndReadEpochAreIndependent() {
        let layer = DTLSRecordLayer()
        let (key, iv) = Self.makeTestKeys()

        // Install write keys only
        layer.setWriteKeys(key: key, fixedIV: iv)
        #expect(layer.writeEpoch == 1)
        #expect(layer.readEpoch == 0, "Read epoch should not change when write keys are set")

        // Install read keys
        layer.setReadKeys(key: key, fixedIV: iv)
        #expect(layer.readEpoch == 1)
        #expect(layer.writeEpoch == 1, "Write epoch should not change when read keys are set")
    }

    // MARK: - Contract C: Encryption After Key Installation

    @Test("Record after key installation is encrypted")
    func recordAfterKeyInstallationIsEncrypted() throws {
        let layer = DTLSRecordLayer()
        let plaintext = Data("secret message".utf8)

        let (key, iv) = Self.makeTestKeys()
        layer.setWriteKeys(key: key, fixedIV: iv)

        let encoded = try layer.encodeRecord(
            contentType: .applicationData,
            plaintext: plaintext
        )

        // Decode raw record without decryption
        guard let (record, _) = try DTLSRecord.decode(from: encoded) else {
            Issue.record("Failed to decode record")
            return
        }

        // Fragment should contain: explicit nonce (8) + ciphertext (same as plaintext) + GCM tag (16)
        let expectedSize = plaintext.count + 8 + 16
        #expect(record.fragment.count == expectedSize,
                "Encrypted fragment should be plaintext + 8 (nonce) + 16 (tag)")
        #expect(record.fragment != plaintext, "Fragment should not be plaintext")
    }

    @Test("Encrypt-decrypt roundtrip through two record layers")
    func encryptDecryptRoundtripThroughRecordLayer() throws {
        let writer = DTLSRecordLayer()
        let reader = DTLSRecordLayer()
        let plaintext = Data("roundtrip test".utf8)

        let (key, iv) = Self.makeTestKeys()

        // Writer encrypts with these keys
        writer.setWriteKeys(key: key, fixedIV: iv)
        // Reader decrypts with the same keys
        reader.setReadKeys(key: key, fixedIV: iv)

        let encoded = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: plaintext
        )

        guard let (decoded, _) = try reader.decodeRecord(from: encoded) else {
            Issue.record("Failed to decode record")
            return
        }

        #expect(decoded.fragment == plaintext)
        #expect(decoded.contentType == .applicationData)
    }

    @Test("Decryption fails with wrong read keys")
    func decryptionFailsWithWrongReadKeys() throws {
        let writer = DTLSRecordLayer()
        let reader = DTLSRecordLayer()

        let (writeKey, writeIV) = Self.makeTestKeys()
        let (readKey, readIV) = Self.makeAlternateKeys()

        writer.setWriteKeys(key: writeKey, fixedIV: writeIV)
        reader.setReadKeys(key: readKey, fixedIV: readIV)

        let encoded = try writer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data("secret".utf8)
        )

        #expect(throws: (any Error).self) {
            _ = try reader.decodeRecord(from: encoded)
        }
    }

    // MARK: - Contract D: Sequence Number Reset on Epoch Change

    @Test("Sequence number resets after epoch change")
    func sequenceNumberResetsAfterEpochChange() throws {
        let layer = DTLSRecordLayer()

        // Send 5 records at epoch 0 (seqNum reaches 4)
        for _ in 0..<5 {
            _ = try layer.encodeRecord(
                contentType: .handshake,
                plaintext: Data([0x00])
            )
        }

        // Install write keys → epoch 1
        let (key, iv) = Self.makeTestKeys()
        layer.setWriteKeys(key: key, fixedIV: iv)

        // Next record should have sequenceNumber 0 at epoch 1
        let encoded = try layer.encodeRecord(
            contentType: .applicationData,
            plaintext: Data([0x42])
        )
        guard let (record, _) = try DTLSRecord.decode(from: encoded) else {
            Issue.record("Failed to decode record")
            return
        }

        #expect(record.epoch == 1)
        #expect(record.sequenceNumber == 0,
                "Sequence number should reset to 0 after epoch change")
    }
}
