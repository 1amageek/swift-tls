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
///
/// ## Architecture (crypto-seam slice)
///
/// The record AEAD logic (explicit-nonce assembly, output framing) lives in the
/// Embedded-clean `DTLSRecordCore.DTLSRecordProtector` value type, generic over
/// the `CryptoProvider.AEAD` seam. This adapter:
/// - keeps the existing stateless static `seal`/`open` API (sequence/epoch state
///   stays in `DTLSRecordLayer`/`DTLSSession`, passed in as values),
/// - specialises the core at `C = TLSFoundationProvider`, `A = DTLSRecordAEAD`
///   (swift-crypto AES-GCM, byte-identical to the legacy direct-Crypto path),
/// - bridges `Data` ↔ `[UInt8]`/`SymmetricKey` at the boundary,
/// - bridges the core's typed `DTLSRecordProtectionError` to the public
///   `DTLSRecordError` so behavior is unchanged (no silent fallback).

import Foundation
import Crypto
import DTLSCore
import DTLSRecordCore

/// DTLS 1.2 AEAD record encryption/decryption
public enum DTLSRecordCryptor: Sendable {

    /// The concrete protector type the host adapter specialises.
    private typealias Protector = DTLSRecordProtector<TLSFoundationProvider, DTLSRecordAEAD>

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
        let protector = try makeProtector(key: key, fixedIV: fixedIV)
        do {
            let output = try protector.seal(
                plaintext: [UInt8](plaintext),
                explicitNonce: [UInt8](explicitNonce),
                aad: [UInt8](additionalData)
            )
            return Data(output)
        } catch let error as DTLSRecordProtectionError {
            throw mapSealError(error)
        }
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
        let protector = try makeProtector(key: key, fixedIV: fixedIV)
        do {
            let plaintext = try protector.open(
                ciphertext: [UInt8](ciphertext),
                aad: [UInt8](additionalData)
            )
            return Data(plaintext)
        } catch let error as DTLSRecordProtectionError {
            throw mapOpenError(error)
        }
    }

    // MARK: - Private helpers

    private static func makeProtector(key: SymmetricKey, fixedIV: Data) throws -> Protector {
        let keyBytes = [UInt8](key.withUnsafeBytes { Data($0) })
        do {
            return try Protector(aead: DTLSRecordAEAD(key: keyBytes), fixedIV: [UInt8](fixedIV))
        } catch let error as DTLSRecordProtectionError {
            throw mapSealError(error)
        }
    }

    /// Maps protection errors raised on the encrypt path to `DTLSRecordError`,
    /// preserving the legacy messages.
    private static func mapSealError(_ error: DTLSRecordProtectionError) -> DTLSRecordError {
        switch error {
        case .invalidFixedIVLength:
            return .encryptionFailed("Fixed IV must be 4 bytes")
        case .invalidExplicitNonceLength:
            return .encryptionFailed("Explicit nonce must be 8 bytes")
        case .ciphertextTooShort:
            return .encryptionFailed("Ciphertext too short")
        case .decryptionFailed:
            return .encryptionFailed("AEAD failure")
        case .crypto:
            return .encryptionFailed("AEAD failure")
        }
    }

    /// Maps protection errors raised on the decrypt path to `DTLSRecordError`,
    /// preserving the legacy messages.
    private static func mapOpenError(_ error: DTLSRecordProtectionError) -> DTLSRecordError {
        switch error {
        case .invalidFixedIVLength:
            return .decryptionFailed("Fixed IV must be 4 bytes")
        case .invalidExplicitNonceLength:
            return .decryptionFailed("Explicit nonce must be 8 bytes")
        case .ciphertextTooShort:
            return .decryptionFailed("Ciphertext too short")
        case .decryptionFailed, .crypto:
            return .decryptionFailed("AEAD authentication failed")
        }
    }
}
