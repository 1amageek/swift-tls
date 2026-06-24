/// TLS 1.3 Record Cryptor (RFC 8446 Section 5.2)
///
/// Handles AEAD encryption and decryption of TLS records.
///
/// Each record is encrypted with:
/// - Nonce: per-record nonce XOR'd with sequence number
/// - AAD: The TLS ciphertext record header
/// - Inner plaintext: content + ContentType(1 byte) + zero padding
///
/// ## Architecture (crypto-seam slice)
///
/// The record AEAD logic (nonce XOR seq, AAD construction, inner-plaintext
/// padding strip) lives in the Embedded-clean `TLSRecordCore.TLSRecordProtector`
/// value type, generic over the `CryptoProvider.AEAD` seam. This adapter:
/// - holds the `Mutex`-backed sequence-number + protector state (the protector is
///   a value type; the `Mutex` and sequence numbers stay caller-side here),
/// - specialises the core at `C = TLSCryptoProvider`, `A = TLSRecordAEAD`
///   (swift-crypto–backed, byte-identical to the legacy direct-Crypto path),
/// - bridges `Data` ↔ `[UInt8]` at the boundary,
/// - preserves the exact public API and decrypt-failure behavior.
///
/// ## Security Properties
///
/// The protector reports any AEAD-open failure uniformly as `badRecordMac` to
/// avoid leaking information about the nature of decryption failures (padding
/// oracle prevention, RFC 8446 §5.2). No silent fallback.

import Foundation
import TLSCore
import TLSWireCore
import TLSRecordCore
import Synchronization

// MARK: - TLS Record Cryptor

/// AEAD encryption/decryption for TLS 1.3 records
public final class TLSRecordCryptor: Sendable {

    private let state: Mutex<CryptorState>

    /// The cipher suite used for encryption
    public let cipherSuite: CipherSuite

    // MARK: - Initialization

    /// Creates a new record cryptor
    /// - Parameter cipherSuite: The negotiated cipher suite
    public init(cipherSuite: CipherSuite) {
        self.cipherSuite = cipherSuite
        self.state = Mutex(CryptorState())
    }

    // MARK: - Key Management

    /// Update the send (write) keys
    /// - Throws: `TLSRecordError.invalidKey` if IV is not 12 bytes
    public func updateSendKeys(_ keys: TrafficKeys) throws {
        guard keys.iv.count == 12 else {
            throw TLSRecordError.invalidKey("TLS 1.3 IV must be exactly 12 bytes, got \(keys.iv.count)")
        }
        let keyBytes = [UInt8](keys.key.withUnsafeBytes { Data($0) })
        let ivBytes = [UInt8](keys.iv)
        let protector = try Self.makeProtector(key: keyBytes, iv: ivBytes, cipherSuite: cipherSuite)
        state.withLock { state in
            state.sendProtector = protector
            state.sendSequenceNumber = 0
        }
    }

    /// Update the receive (read) keys
    /// - Throws: `TLSRecordError.invalidKey` if IV is not 12 bytes
    public func updateReceiveKeys(_ keys: TrafficKeys) throws {
        guard keys.iv.count == 12 else {
            throw TLSRecordError.invalidKey("TLS 1.3 IV must be exactly 12 bytes, got \(keys.iv.count)")
        }
        let keyBytes = [UInt8](keys.key.withUnsafeBytes { Data($0) })
        let ivBytes = [UInt8](keys.iv)
        let protector = try Self.makeProtector(key: keyBytes, iv: ivBytes, cipherSuite: cipherSuite)
        state.withLock { state in
            state.receiveProtector = protector
            state.receiveSequenceNumber = 0
        }
    }

    // MARK: - Encryption

    /// Encrypt content into a TLS ciphertext record body.
    ///
    /// Creates the "inner plaintext" (content + content type + padding),
    /// then encrypts with AEAD via the Embedded-clean record protector.
    ///
    /// - Parameters:
    ///   - content: The plaintext content
    ///   - type: The content type
    /// - Returns: The ciphertext (encrypted inner plaintext + AEAD tag)
    public func encrypt(content: Data, type: TLSContentType) throws -> Data {
        guard content.count <= TLSRecordCodec.maxPlaintextSize else {
            throw TLSRecordError.plaintextTooLarge(content.count)
        }

        return try state.withLock { state in
            guard let protector = state.sendProtector else {
                throw TLSRecordError.noKeysAvailable
            }

            let ciphertext: [UInt8]
            do {
                ciphertext = try protector.protect(
                    content: [UInt8](content),
                    type: type,
                    sequenceNumber: state.sendSequenceNumber
                )
            } catch let error as TLSRecordProtectionError {
                throw Self.mapProtectionError(error)
            }
            state.sendSequenceNumber += 1
            return Data(ciphertext)
        }
    }

    // MARK: - Decryption

    /// Decrypt a TLS ciphertext record body.
    ///
    /// - Parameter ciphertext: The ciphertext from a TLS record (without record header)
    /// - Returns: A tuple of (decrypted content, content type)
    public func decrypt(ciphertext: Data) throws -> (Data, TLSContentType) {
        return try state.withLock { state in
            guard let protector = state.receiveProtector else {
                throw TLSRecordError.noKeysAvailable
            }

            let result: (content: [UInt8], type: TLSContentType)
            do {
                result = try protector.unprotect(
                    ciphertext: [UInt8](ciphertext),
                    sequenceNumber: state.receiveSequenceNumber
                )
            } catch let error as TLSRecordProtectionError {
                throw Self.mapProtectionError(error)
            }
            state.receiveSequenceNumber += 1
            return (Data(result.content), result.type)
        }
    }

    // MARK: - Private Helpers

    /// The concrete record protector type the host adapter specialises:
    /// the Embedded-clean generic core at `C = TLSCryptoProvider`,
    /// `A = TLSRecordAEAD` (swift-crypto–backed).
    private typealias Protector = TLSRecordProtector<TLSCryptoProvider, TLSRecordAEAD>

    private struct CryptorState: Sendable {
        /// The send (write) protector (value type). The sequence number stays here
        /// (caller-locked); only the AEAD + IV live in the protector. `nil` until
        /// send keys are installed (allows send-only / receive-only key states).
        var sendProtector: Protector?
        var sendSequenceNumber: UInt64 = 0

        /// The receive (read) protector (value type). `nil` until receive keys are
        /// installed.
        var receiveProtector: Protector?
        var receiveSequenceNumber: UInt64 = 0
    }

    /// Builds a single-direction protector from raw key + IV bytes.
    private static func makeProtector(
        key: [UInt8],
        iv: [UInt8],
        cipherSuite: CipherSuite
    ) throws -> Protector {
        do {
            return try Protector(
                aead: TLSRecordAEAD(key: key, cipherSuite: cipherSuite),
                iv: iv
            )
        } catch let error as TLSRecordProtectionError {
            throw Self.mapProtectionError(error)
        }
    }

    /// Maps the core's typed protection error onto the public `TLSRecordError`,
    /// preserving the exact behavior the legacy cryptor exposed.
    private static func mapProtectionError(_ error: TLSRecordProtectionError) -> TLSRecordError {
        switch error {
        case .invalidIVLength(let expected, let actual):
            return .invalidKey("TLS 1.3 IV must be exactly \(expected) bytes, got \(actual)")
        case .plaintextTooLarge(let size):
            return .plaintextTooLarge(size)
        case .sequenceNumberOverflow:
            return .sequenceNumberOverflow
        case .ciphertextTooShort, .badRecordMac, .crypto:
            return .badRecordMac
        case .invalidInnerPlaintext:
            return .invalidInnerPlaintext
        }
    }
}
