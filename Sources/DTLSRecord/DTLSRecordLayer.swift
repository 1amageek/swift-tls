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
import TLSCore
import DTLSCore
import DTLSWireCore
import DTLSRecordCore

/// DTLS record layer managing epoch/sequence and encryption state
public final class DTLSRecordLayer: Sendable {
    /// Explicit nonce length carried in each AEAD record (epoch + sequence prefix).
    private static let explicitNonceSize = 8
    /// AES-GCM authentication tag length.
    private static let aeadTagSize = 16
    /// Minimum size of an encrypted fragment: explicit nonce + tag (zero-length plaintext).
    static let aeadOverhead = explicitNonceSize + aeadTagSize // 24

    /// Maximum 48-bit DTLS sequence number; the layer must rekey before this wraps.
    private static let maxSequenceNumber: UInt64 = (1 << 48) - 1

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
        let (epoch, seqNum, key, fixedIV) = try state.withLock { s -> (UInt16, UInt64, SymmetricKey?, Data?) in
            // RFC 6347 §4.1: the 48-bit per-epoch sequence number must never wrap.
            // Refuse to emit a record once the space is exhausted; the caller must
            // rekey (advance the epoch) rather than silently reusing a nonce.
            guard s.writeSequenceNumber <= Self.maxSequenceNumber else {
                throw DTLSRecordError.sequenceNumberOverflow
            }
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
            let aad = try record.buildAAD(plaintextLength: plaintext.count)
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
            // Validate the fragment before touching the replay window or building AAD.
            // A short fragment cannot carry the AEAD overhead (8-byte explicit nonce +
            // 16-byte tag); RFC 6347 §4.1.2.7 requires a silent discard, never a crash.
            guard record.fragment.count >= Self.aeadOverhead else {
                return .discarded(consumed: consumed, reason: .malformed)
            }
            let plaintextLength = record.fragment.count - Self.aeadOverhead
            guard plaintextLength <= DTLSRecord.maxPlaintextSize else {
                return .discarded(consumed: consumed, reason: .malformed)
            }

            // RFC 6347 §4.1.2.6: the replay check, the AEAD authentication, and the
            // window update must be one atomic transaction so a concurrent replay
            // cannot both pass the preliminary check and update the window twice.
            // AEAD is CPU-only (no suspension), so it is permitted under the Mutex.
            return state.withLock { s -> RecordDecodeResult in
                let seqNum = record.sequenceNumber

                // Preliminary replay check (no state mutation yet).
                if s.replayWindow.isInitialized {
                    let highest = s.replayWindow.currentHighest
                    if seqNum <= highest {
                        let diff = highest - seqNum
                        if diff >= AntiReplayWindow.windowSize {
                            return .discarded(consumed: consumed, reason: .tooOld)
                        }
                        if s.replayWindow.isReceived(sequenceNumber: seqNum) {
                            return .discarded(consumed: consumed, reason: .replayed)
                        }
                    }
                }

                // Build AAD; an out-of-range length is a malformed record, not a fatal
                // local error, so map it to a discard.
                let aad: Data
                do {
                    aad = try record.buildAAD(plaintextLength: plaintextLength)
                } catch {
                    return .discarded(consumed: consumed, reason: .malformed)
                }

                // Authenticate + decrypt. A bad MAC is a forged/corrupt record:
                // discard it and let the datagram loop continue (RFC 6347 §4.1.2.7).
                let plaintext: Data
                do {
                    plaintext = try DTLSRecordCryptor.open(
                        ciphertext: record.fragment,
                        key: key,
                        fixedIV: fixedIV,
                        additionalData: aad
                    )
                } catch {
                    return .discarded(consumed: consumed, reason: .authenticationFailed)
                }

                // Authentication succeeded: now commit the window update. If the window
                // rejects the sequence here (lost a concurrent race), surface it as a
                // replay discard rather than silently ignoring the result.
                guard s.replayWindow.shouldAccept(sequenceNumber: seqNum) else {
                    return .discarded(consumed: consumed, reason: .replayed)
                }

                var decryptedRecord = record
                decryptedRecord.fragment = plaintext
                return .record(decryptedRecord, consumed: consumed)
            }
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
