/// DTLS 1.2 Record Cryptor (RFC 5288 — AES-GCM for TLS)
///
/// DTLS 1.2 uses explicit nonce construction:
///   nonce = fixed_IV (4 bytes) || explicit_nonce (8 bytes)
/// where explicit_nonce = epoch (2 bytes) || sequence_number (6 bytes)
///
/// AAD = epoch + seq_num + content_type + version + plaintext_length
///
/// This differs from TLS 1.3 which uses:
///   nonce = IV XOR sequence_number (implicit)

import Foundation
import Crypto
import DTLSCore

/// DTLS 1.2 AEAD record encryption/decryption
public enum DTLSRecordCryptor: Sendable {

    /// Encrypt a plaintext record payload using AES-GCM
    /// - Parameters:
    ///   - plaintext: The plaintext to encrypt
    ///   - key: The symmetric encryption key
    ///   - fixedIV: Fixed part of the IV (4 bytes, from key_block)
    ///   - explicitNonce: Explicit nonce (8 bytes, epoch + sequence_number)
    ///   - additionalData: AAD from the record header
    /// - Returns: explicit_nonce (8) + ciphertext + tag (16)
    public static func seal(
        plaintext: Data,
        key: SymmetricKey,
        fixedIV: Data,
        explicitNonce: Data,
        additionalData: Data
    ) throws -> Data {
        guard fixedIV.count == 4 else {
            throw DTLSRecordError.encryptionFailed("Fixed IV must be 4 bytes")
        }
        guard explicitNonce.count == 8 else {
            throw DTLSRecordError.encryptionFailed("Explicit nonce must be 8 bytes")
        }

        // nonce = fixed_IV (4) + explicit_nonce (8) = 12 bytes
        let nonce = fixedIV + explicitNonce

        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: additionalData
        )

        // Output: explicit_nonce + ciphertext + tag
        return explicitNonce + sealedBox.ciphertext + sealedBox.tag
    }

    /// Decrypt a ciphertext record payload using AES-GCM
    /// - Parameters:
    ///   - ciphertext: explicit_nonce (8) + encrypted_data + tag (16)
    ///   - key: The symmetric decryption key
    ///   - fixedIV: Fixed part of the IV (4 bytes, from key_block)
    ///   - additionalData: AAD from the record header
    /// - Returns: Decrypted plaintext
    public static func open(
        ciphertext: Data,
        key: SymmetricKey,
        fixedIV: Data,
        additionalData: Data
    ) throws -> Data {
        guard fixedIV.count == 4 else {
            throw DTLSRecordError.decryptionFailed("Fixed IV must be 4 bytes")
        }

        // Minimum: 8 (explicit nonce) + 0 (data) + 16 (tag) = 24 bytes
        guard ciphertext.count >= 24 else {
            throw DTLSRecordError.decryptionFailed("Ciphertext too short")
        }

        // Extract explicit nonce (first 8 bytes)
        let explicitNonce = ciphertext.prefix(8)
        let encryptedData = ciphertext.dropFirst(8)

        // nonce = fixed_IV (4) + explicit_nonce (8)
        let nonce = fixedIV + explicitNonce

        // Split ciphertext and tag
        let tagStart = encryptedData.count - 16
        let encrypted = encryptedData.prefix(tagStart)
        let tag = encryptedData.suffix(16)

        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: encrypted,
            tag: tag
        )

        return try AES.GCM.open(sealedBox, using: key, authenticating: additionalData)
    }
}
