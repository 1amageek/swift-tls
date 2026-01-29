/// DTLS 1.2 Record Layer (RFC 6347 Section 4.1)
///
/// Manages epoch and sequence numbers for DTLS record processing.
/// Epoch increments on each ChangeCipherSpec. Sequence number is per-epoch.
///
/// ## RFC 6347 Compliance
///
/// - **§4.1**: Epoch mismatch records are silently discarded
/// - **§4.1.2.6**: 64-bit sliding window anti-replay protection
/// - **§4.1.2.6**: Replay window updated only after successful MAC verification
/// - **§4.1.2.7**: Invalid records are silently discarded (no fatal alert)

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

        // Anti-replay protection (RFC 6347 §4.1.2.6)
        var replayWindow: AntiReplayWindow = AntiReplayWindow()
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
            // Reset replay window on epoch change
            s.replayWindow.reset()
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
    /// - Returns: `RecordDecodeResult` indicating success, insufficient data, or discard reason
    public func decodeRecord(from data: Data) throws -> RecordDecodeResult {
        guard let (record, consumed) = try DTLSRecord.decode(from: data) else {
            return .insufficientData
        }

        let (readEpoch, key, fixedIV) = state.withLock { s -> (UInt16, SymmetricKey?, Data?) in
            (s.readEpoch, s.readKey, s.readFixedIV)
        }

        // RFC 6347 §4.1: Check epoch before processing
        // Records from different epochs should be silently discarded
        if record.epoch != readEpoch {
            // Epoch mismatch - silently discard (RFC 6347 §4.1)
            // "implementations SHOULD discard packets from earlier epochs"
            return .discarded(consumed: consumed, reason: .epochMismatch)
        }

        if let key, let fixedIV, record.epoch > 0 {
            // For encrypted records: check replay window BEFORE decryption (preliminary check)
            // but only UPDATE the window AFTER successful decryption (RFC 6347 §4.1.2.6)
            let replayCheckResult = state.withLock { s -> DiscardReason? in
                // Preliminary check: would this sequence number be accepted?
                // Don't mark as received yet - just check
                if !s.replayWindow.isInitialized {
                    return nil  // First packet, will be accepted
                }
                let seqNum = record.sequenceNumber
                let highest = s.replayWindow.currentHighest
                if seqNum > highest {
                    return nil  // New highest, will be accepted
                }
                let diff = highest - seqNum
                if diff >= AntiReplayWindow.windowSize {
                    return .tooOld  // Too old
                }
                // Check if already received (without modifying state)
                if s.replayWindow.isReceived(sequenceNumber: seqNum) {
                    return .replayed
                }
                return nil
            }

            if let discardReason = replayCheckResult {
                // Silently discard replayed/too-old records (RFC 6347 §4.1.2.6)
                // Return consumed bytes so caller can continue to next record
                return .discarded(consumed: consumed, reason: discardReason)
            }

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

            // Decryption succeeded - NOW update the replay window (RFC 6347 §4.1.2.6)
            state.withLock { s in
                _ = s.replayWindow.shouldAccept(sequenceNumber: record.sequenceNumber)
            }

            var decryptedRecord = record
            decryptedRecord.fragment = plaintext
            return .record(decryptedRecord, consumed: consumed)
        }

        // Unencrypted records (epoch 0) don't use replay protection
        return .record(record, consumed: consumed)
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
