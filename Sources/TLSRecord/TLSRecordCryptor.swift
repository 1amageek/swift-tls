/// TLS 1.3 Record Cryptor (RFC 8446 Section 5.2)
///
/// Handles AEAD encryption and decryption of TLS records.
///
/// Each record is encrypted with:
/// - Nonce: per-record nonce XOR'd with sequence number
/// - AAD: The TLS ciphertext record header
/// - Inner plaintext: content + ContentType(1 byte) + zero padding
///
/// ## Security Properties
///
/// This implementation uses Apple CryptoKit's AES-GCM and ChaChaPoly,
/// which provide constant-time AEAD operations. The decrypt method
/// catches all CryptoKit errors uniformly as `badRecordMac` to avoid
/// leaking information about the nature of decryption failures
/// (padding oracle prevention).

import Foundation
import TLSCore
import Crypto
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
    public func updateSendKeys(_ keys: TrafficKeys) {
        state.withLock { state in
            precondition(keys.iv.count == 12, "TLS 1.3 IV must be exactly 12 bytes")
            state.sendKey = keys.key
            state.sendIV = keys.iv
            state.sendSequenceNumber = 0
        }
    }

    /// Update the receive (read) keys
    public func updateReceiveKeys(_ keys: TrafficKeys) {
        state.withLock { state in
            precondition(keys.iv.count == 12, "TLS 1.3 IV must be exactly 12 bytes")
            state.receiveKey = keys.key
            state.receiveIV = keys.iv
            state.receiveSequenceNumber = 0
        }
    }

    // MARK: - Encryption

    /// Encrypt content into a TLS ciphertext record body.
    ///
    /// Creates the "inner plaintext" (content + content type + padding),
    /// then encrypts with AEAD.
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
            guard let key = state.sendKey, let iv = state.sendIV else {
                throw TLSRecordError.noKeysAvailable
            }

            // Build inner plaintext: content + content_type
            var innerPlaintext = Data(capacity: content.count + 1)
            innerPlaintext.append(content)
            innerPlaintext.append(type.rawValue)

            // Build nonce: IV XOR sequence number
            let nonce = Self.buildNonce(iv: iv, sequenceNumber: state.sendSequenceNumber)

            // Build AAD: record header for the ciphertext record
            // ContentType(0x17) + Version(0x0303) + Length(ciphertext length)
            let ciphertextLength = innerPlaintext.count + Self.tagLength(for: cipherSuite)
            let aad = Self.buildAAD(ciphertextLength: ciphertextLength)

            // Encrypt
            let ciphertext = try Self.aeadSeal(
                plaintext: innerPlaintext,
                key: key,
                nonce: nonce,
                aad: aad,
                cipherSuite: cipherSuite
            )

            guard state.sendSequenceNumber < UInt64.max else {
                throw TLSRecordError.sequenceNumberOverflow
            }
            state.sendSequenceNumber += 1
            return ciphertext
        }
    }

    // MARK: - Decryption

    /// Decrypt a TLS ciphertext record body.
    ///
    /// - Parameter ciphertext: The ciphertext from a TLS record (without record header)
    /// - Returns: A tuple of (decrypted content, content type)
    public func decrypt(ciphertext: Data) throws -> (Data, TLSContentType) {
        return try state.withLock { state in
            guard let key = state.receiveKey, let iv = state.receiveIV else {
                throw TLSRecordError.noKeysAvailable
            }

            // Build nonce
            let nonce = Self.buildNonce(iv: iv, sequenceNumber: state.receiveSequenceNumber)

            // Build AAD
            let aad = Self.buildAAD(ciphertextLength: ciphertext.count)

            // Decrypt
            let innerPlaintext = try Self.aeadOpen(
                ciphertext: ciphertext,
                key: key,
                nonce: nonce,
                aad: aad,
                cipherSuite: cipherSuite
            )

            guard state.receiveSequenceNumber < UInt64.max else {
                throw TLSRecordError.sequenceNumberOverflow
            }
            state.receiveSequenceNumber += 1

            // Parse inner plaintext: find the real content type
            // Strip trailing zeros (padding), then the last non-zero byte is the content type
            guard let (content, contentType) = Self.parseInnerPlaintext(innerPlaintext) else {
                throw TLSRecordError.invalidInnerPlaintext
            }

            return (content, contentType)
        }
    }

    // MARK: - Private Helpers

    private struct CryptorState: Sendable {
        var sendKey: SymmetricKey?
        var sendIV: Data?
        var sendSequenceNumber: UInt64 = 0

        var receiveKey: SymmetricKey?
        var receiveIV: Data?
        var receiveSequenceNumber: UInt64 = 0
    }

    /// Build the per-record nonce (RFC 8446 Section 5.3)
    /// Nonce = IV XOR sequence_number (padded to IV length)
    private static func buildNonce(iv: Data, sequenceNumber: UInt64) -> Data {
        var nonce = iv
        let seqBytes = withUnsafeBytes(of: sequenceNumber.bigEndian) { Data($0) }

        // XOR the sequence number into the last 8 bytes of the IV
        let offset = nonce.count - 8
        for i in 0..<8 {
            nonce[nonce.startIndex + offset + i] ^= seqBytes[i]
        }
        return nonce
    }

    /// Build AAD for AEAD (the ciphertext record header)
    private static func buildAAD(ciphertextLength: Int) -> Data {
        var aad = Data(capacity: 5)
        aad.append(TLSContentType.applicationData.rawValue) // 0x17
        aad.append(0x03) // Version high
        aad.append(0x03) // Version low
        aad.append(UInt8(ciphertextLength >> 8))
        aad.append(UInt8(ciphertextLength & 0xFF))
        return aad
    }

    /// Parse inner plaintext to extract content and content type
    /// Inner plaintext = content + ContentType(1) + zeros(padding)
    private static func parseInnerPlaintext(_ data: Data) -> (Data, TLSContentType)? {
        guard !data.isEmpty else { return nil }

        // Find the last non-zero byte (content type)
        var idx = data.endIndex - 1
        while idx >= data.startIndex && data[idx] == 0 {
            idx -= 1
        }

        guard idx >= data.startIndex else { return nil }
        guard let contentType = TLSContentType(rawValue: data[idx]) else { return nil }

        let content = data[data.startIndex..<idx]
        return (Data(content), contentType)
    }

    /// AEAD tag length for the cipher suite
    private static func tagLength(for cipherSuite: CipherSuite) -> Int {
        16 // All TLS 1.3 cipher suites use 16-byte tags
    }

    /// AEAD seal (encrypt + authenticate)
    private static func aeadSeal(
        plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        aad: Data,
        cipherSuite: CipherSuite
    ) throws -> Data {
        switch cipherSuite {
        case .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384:
            let aeadNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: aeadNonce,
                authenticating: aad
            )
            // Return ciphertext + tag combined
            return sealedBox.ciphertext + sealedBox.tag

        case .tls_chacha20_poly1305_sha256:
            let aeadNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.seal(
                plaintext,
                using: key,
                nonce: aeadNonce,
                authenticating: aad
            )
            return sealedBox.ciphertext + sealedBox.tag
        }
    }

    /// AEAD open (decrypt + verify)
    private static func aeadOpen(
        ciphertext: Data,
        key: SymmetricKey,
        nonce: Data,
        aad: Data,
        cipherSuite: CipherSuite
    ) throws -> Data {
        let tagSize = tagLength(for: cipherSuite)
        guard ciphertext.count >= tagSize else {
            throw TLSRecordError.badRecordMac
        }

        let splitIndex = ciphertext.count - tagSize
        let encryptedData = Data(ciphertext.prefix(splitIndex))
        let tag = Data(ciphertext.suffix(tagSize))

        do {
            switch cipherSuite {
            case .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384:
                let aeadNonce = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(
                    nonce: aeadNonce,
                    ciphertext: encryptedData,
                    tag: tag
                )
                return try AES.GCM.open(sealedBox, using: key, authenticating: aad)

            case .tls_chacha20_poly1305_sha256:
                let aeadNonce = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(
                    nonce: aeadNonce,
                    ciphertext: encryptedData,
                    tag: tag
                )
                return try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
            }
        } catch {
            throw TLSRecordError.badRecordMac
        }
    }
}
