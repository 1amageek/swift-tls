/// DTLS 1.2 Record Layer (RFC 6347 Section 4.1)
///
/// Manages epoch and sequence numbers for DTLS record processing.
/// Epoch increments on each ChangeCipherSpec. Sequence number is per-epoch.

import Foundation
import Synchronization
import Crypto
import DTLSCore

/// DTLS record layer managing epoch/sequence and encryption state
public final class DTLSRecordLayer: Sendable {
    private let state: Mutex<RecordLayerState>

    private struct RecordLayerState: Sendable {
        var readEpoch: UInt16 = 0
        var writeEpoch: UInt16 = 0
        var readSequenceNumber: UInt64 = 0
        var writeSequenceNumber: UInt64 = 0

        // Encryption keys (nil before CCS)
        var readKey: SymmetricKey?
        var readFixedIV: Data?
        var writeKey: SymmetricKey?
        var writeFixedIV: Data?
    }

    public init() {
        self.state = Mutex(RecordLayerState())
    }

    /// Set write keys and advance write epoch
    public func setWriteKeys(key: SymmetricKey, fixedIV: Data) {
        state.withLock { s in
            s.writeEpoch += 1
            s.writeSequenceNumber = 0
            s.writeKey = key
            s.writeFixedIV = fixedIV
        }
    }

    /// Set read keys and advance read epoch
    public func setReadKeys(key: SymmetricKey, fixedIV: Data) {
        state.withLock { s in
            s.readEpoch += 1
            s.readSequenceNumber = 0
            s.readKey = key
            s.readFixedIV = fixedIV
        }
    }

    /// Encrypt and encode a record for sending
    /// - Parameters:
    ///   - contentType: The content type
    ///   - plaintext: The plaintext payload
    /// - Returns: The encoded DTLS record
    public func encodeRecord(
        contentType: DTLSContentType,
        plaintext: Data
    ) throws -> Data {
        let (epoch, seqNum, key, fixedIV) = state.withLock { s -> (UInt16, UInt64, SymmetricKey?, Data?) in
            let result = (s.writeEpoch, s.writeSequenceNumber, s.writeKey, s.writeFixedIV)
            s.writeSequenceNumber += 1
            return result
        }

        // Build explicit nonce from epoch + sequence number
        let explicitNonce = buildExplicitNonce(epoch: epoch, sequenceNumber: seqNum)

        var record = DTLSRecord(
            contentType: contentType,
            epoch: epoch,
            sequenceNumber: seqNum,
            fragment: plaintext
        )

        if let key, let fixedIV {
            // Encrypted record
            let aad = record.buildAAD(plaintextLength: plaintext.count)
            let encrypted = try DTLSRecordCryptor.seal(
                plaintext: plaintext,
                key: key,
                fixedIV: fixedIV,
                explicitNonce: explicitNonce,
                additionalData: aad
            )
            record.fragment = encrypted
        }

        return record.encode()
    }

    /// Decode and decrypt a received record
    /// - Parameter data: Raw DTLS record data
    /// - Returns: Decoded record with decrypted payload, or nil if insufficient data
    public func decodeRecord(from data: Data) throws -> (DTLSRecord, Int)? {
        guard let (record, consumed) = try DTLSRecord.decode(from: data) else {
            return nil
        }

        let (key, fixedIV) = state.withLock { s -> (SymmetricKey?, Data?) in
            (s.readKey, s.readFixedIV)
        }

        if let key, let fixedIV, record.epoch > 0 {
            // Decrypt
            let aad = record.buildAAD(
                plaintextLength: record.fragment.count - 8 - 16 // subtract nonce and tag
            )
            let plaintext = try DTLSRecordCryptor.open(
                ciphertext: record.fragment,
                key: key,
                fixedIV: fixedIV,
                additionalData: aad
            )

            var decryptedRecord = record
            decryptedRecord.fragment = plaintext
            return (decryptedRecord, consumed)
        }

        return (record, consumed)
    }

    /// Current write epoch
    public var writeEpoch: UInt16 {
        state.withLock { $0.writeEpoch }
    }

    /// Current read epoch
    public var readEpoch: UInt16 {
        state.withLock { $0.readEpoch }
    }

    // MARK: - Private

    private func buildExplicitNonce(epoch: UInt16, sequenceNumber: UInt64) -> Data {
        var writer = TLSWriter()
        writer.writeUInt16(epoch)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))
        return writer.finish()
    }
}
