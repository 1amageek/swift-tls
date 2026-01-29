/// Record Security Edge Case Tests
///
/// Tests AEAD encryption boundary conditions and security properties.
/// Verifies tamper detection, nonce uniqueness, sequence number handling,
/// and maximum plaintext size enforcement.

import Testing
import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

@Suite("Record Security Edge Case Tests")
struct RecordSecurityEdgeCaseTests {

    /// Creates a pair of TrafficKeys for testing
    private static func makeTestKeys(
        cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256
    ) -> (send: TrafficKeys, receive: TrafficKeys) {
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: cipherSuite)
        return (keys, keys)
    }

    // MARK: - Tamper Detection

    @Test("Tampered ciphertext fails decryption")
    func tamperedCiphertextFailsDecryption() throws {
        let (sendKeys, recvKeys) = Self.makeTestKeys()
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try cryptor.updateSendKeys(sendKeys)
        try cryptor.updateReceiveKeys(recvKeys)

        let plaintext = Data("sensitive data".utf8)
        let ciphertext = try cryptor.encrypt(content: plaintext, type: .applicationData)

        // Tamper with one byte in the middle
        var tampered = ciphertext
        tampered[tampered.count / 2] ^= 0xFF

        #expect(throws: TLSRecordError.self) {
            _ = try cryptor.decrypt(ciphertext: tampered)
        }
    }

    @Test("Out of order decryption fails")
    func outOfOrderDecryptionFails() throws {
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)

        let encryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try encryptor.updateSendKeys(keys)

        let decryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try decryptor.updateReceiveKeys(keys)

        // Encrypt two records (seq 0 and seq 1)
        let ct0 = try encryptor.encrypt(content: Data("first".utf8), type: .applicationData)
        let ct1 = try encryptor.encrypt(content: Data("second".utf8), type: .applicationData)

        // Decrypt in wrong order: try ct1 first (decryptor expects seq 0)
        #expect(throws: TLSRecordError.self) {
            _ = try decryptor.decrypt(ciphertext: ct1)
        }

        // Decrypting ct0 should still work (seq 0 matches)
        let (decrypted, _) = try decryptor.decrypt(ciphertext: ct0)
        #expect(decrypted == Data("first".utf8))
    }

    // MARK: - Boundary Conditions

    @Test("Record exactly at max plaintext size")
    func recordExactlyAtMaxPlaintextSize() throws {
        let (sendKeys, recvKeys) = Self.makeTestKeys()
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try cryptor.updateSendKeys(sendKeys)
        try cryptor.updateReceiveKeys(recvKeys)

        let maxData = Data(repeating: 0xAB, count: TLSRecordCodec.maxPlaintextSize)
        let ciphertext = try cryptor.encrypt(content: maxData, type: .applicationData)
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)

        #expect(decrypted == maxData)
        #expect(contentType == .applicationData)
    }

    @Test("Zero length content encrypt decrypt")
    func zeroLengthContentEncryptDecrypt() throws {
        let (sendKeys, recvKeys) = Self.makeTestKeys()
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try cryptor.updateSendKeys(sendKeys)
        try cryptor.updateReceiveKeys(recvKeys)

        let emptyData = Data()
        let ciphertext = try cryptor.encrypt(content: emptyData, type: .applicationData)
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)

        #expect(decrypted == emptyData)
        #expect(contentType == .applicationData)
    }

    // MARK: - Sequence Number Handling

    @Test("Many records sequentially succeed")
    func manyRecordsSequentiallySucceed() throws {
        let (sendKeys, recvKeys) = Self.makeTestKeys()
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try cryptor.updateSendKeys(sendKeys)
        try cryptor.updateReceiveKeys(recvKeys)

        for i in 0..<100 {
            let data = Data("record \(i)".utf8)
            let ciphertext = try cryptor.encrypt(content: data, type: .applicationData)
            let (decrypted, _) = try cryptor.decrypt(ciphertext: ciphertext)
            #expect(decrypted == data)
        }
    }

    // MARK: - Nonce Uniqueness

    @Test("Identical plaintexts produce different ciphertexts")
    func identicalPlaintextsProduceDifferentCiphertexts() throws {
        let (sendKeys, _) = Self.makeTestKeys()
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        try cryptor.updateSendKeys(sendKeys)

        let plaintext = Data("same content".utf8)

        // Encrypt the same plaintext twice (different sequence numbers → different nonces)
        let ct1 = try cryptor.encrypt(content: plaintext, type: .applicationData)
        let ct2 = try cryptor.encrypt(content: plaintext, type: .applicationData)

        #expect(ct1 != ct2)
    }

    // MARK: - Key Update

    @Test("Key update produces new secrets")
    func keyUpdateProducesNewSecrets() async throws {
        let result = try await performFullHandshake()

        let clientAK = try #require(result.clientAppKeys)
        let originalClientSecret = try #require(clientAK.clientSecret)

        // Request key update on client
        let updateOutputs = try await result.clientHandler.requestKeyUpdate()

        // RFC 8446 Section 4.6.3: requestKeyUpdate should:
        // 1. Emit a handshakeData with the KeyUpdate message
        // 2. Emit keysAvailable with only the send (client) secret updated
        //    (receive keys update when peer's KeyUpdate arrives)
        var handshakeDataFound = false
        var newKeys: KeysAvailableInfo?
        for output in updateOutputs {
            if case .handshakeData = output {
                handshakeDataFound = true
            }
            if case .keysAvailable(let info) = output {
                newKeys = info
            }
        }

        #expect(handshakeDataFound, "KeyUpdate message should be emitted")

        let updatedKeys = try #require(newKeys)
        let newClientSecret = try #require(updatedKeys.clientSecret)

        // Only send (client) secret is updated; receive (server) secret is nil
        #expect(updatedKeys.serverSecret == nil, "Receive secret should not be updated until peer's KeyUpdate arrives")
        #expect(newClientSecret != originalClientSecret)
        #expect(updatedKeys.level == .application)
    }
}
