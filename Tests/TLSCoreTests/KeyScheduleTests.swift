/// TLS 1.3 Key Schedule Tests

import Testing
import Foundation
import Crypto
@testable import TLSCore

@Suite("TLS Key Schedule Tests")
struct KeyScheduleTests {

    // MARK: - Basic Key Schedule Tests

    @Test("Key schedule derives early secret")
    func deriveEarlySecret() throws {
        var keySchedule = TLSKeySchedule()
        keySchedule.deriveEarlySecret(psk: nil)
        // Should not throw, just verify it can be called
    }

    @Test("Key schedule derives handshake secrets")
    func deriveHandshakeSecrets() throws {
        var keySchedule = TLSKeySchedule()

        // Create a shared secret via key agreement
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        let transcriptHash = Data(repeating: 0xAA, count: 32)

        let (clientSecret, serverSecret) = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        #expect(clientSecret.bitCount == 256)
        #expect(serverSecret.bitCount == 256)
    }

    @Test("Key schedule derives application secrets")
    func deriveApplicationSecrets() throws {
        var keySchedule = TLSKeySchedule()

        // First derive handshake secrets
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let hsTranscript = Data(repeating: 0xAA, count: 32)

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hsTranscript
        )

        // Then derive application secrets
        let appTranscript = Data(repeating: 0xBB, count: 32)
        let (clientAppSecret, serverAppSecret) = try keySchedule.deriveApplicationSecrets(
            transcriptHash: appTranscript
        )

        #expect(clientAppSecret.bitCount == 256)
        #expect(serverAppSecret.bitCount == 256)
    }

    @Test("Finished key derivation")
    func deriveFinishedKey() throws {
        let keySchedule = TLSKeySchedule()
        let baseKey = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let finished = keySchedule.finishedKey(from: baseKey)

        #expect(finished.bitCount == 256)
    }

    @Test("Finished verify data computation")
    func computeFinishedVerifyData() throws {
        let keySchedule = TLSKeySchedule()
        let finished = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let transcriptHash = Data(repeating: 0xBB, count: 32)

        let verifyData = keySchedule.finishedVerifyData(
            forKey: finished,
            transcriptHash: transcriptHash
        )

        #expect(verifyData.count == 32) // SHA-256 output
    }

    @Test("Key update derives next secret")
    func keyUpdate() throws {
        let keySchedule = TLSKeySchedule()
        let currentSecret = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let nextSecret = keySchedule.nextApplicationSecret(from: currentSecret)

        #expect(nextSecret.bitCount == 256)
        // Next secret should be different from current
        // (can't directly compare SymmetricKey, but derivation should work)
    }

    // MARK: - Traffic Keys Tests

    @Test("Traffic keys derivation")
    func deriveTrafficKeys() throws {
        let secret = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let trafficKeys = TrafficKeys(secret: secret)

        #expect(trafficKeys.key.bitCount == 128) // AES-128 key
        #expect(trafficKeys.iv.count == 12)       // 12-byte IV
    }

    @Test("Traffic keys with AES-256")
    func deriveTrafficKeysAES256() throws {
        let secret = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let trafficKeys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_256_gcm_sha384)

        #expect(trafficKeys.key.bitCount == 256) // AES-256 key
        #expect(trafficKeys.iv.count == 12)
    }

    // MARK: - Deterministic Derivation Tests

    @Test("Same inputs produce same outputs")
    func deterministicDerivation() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let transcriptHash = Data(repeating: 0xAA, count: 32)

        var keySchedule1 = TLSKeySchedule()
        let (client1, server1) = try keySchedule1.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        var keySchedule2 = TLSKeySchedule()
        let (client2, server2) = try keySchedule2.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        // Same inputs should produce same outputs
        let client1Data = client1.withUnsafeBytes { Data($0) }
        let client2Data = client2.withUnsafeBytes { Data($0) }
        #expect(client1Data == client2Data)

        let server1Data = server1.withUnsafeBytes { Data($0) }
        let server2Data = server2.withUnsafeBytes { Data($0) }
        #expect(server1Data == server2Data)
    }

    @Test("Different transcripts produce different secrets")
    func differentTranscripts() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        var keySchedule1 = TLSKeySchedule()
        let (client1, _) = try keySchedule1.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: Data(repeating: 0xAA, count: 32)
        )

        var keySchedule2 = TLSKeySchedule()
        let (client2, _) = try keySchedule2.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: Data(repeating: 0xBB, count: 32)
        )

        let client1Data = client1.withUnsafeBytes { Data($0) }
        let client2Data = client2.withUnsafeBytes { Data($0) }
        #expect(client1Data != client2Data)
    }

    // MARK: - TranscriptHash Tests

    @Test("TranscriptHash accumulates messages")
    func transcriptHashAccumulates() throws {
        var transcriptHash = TranscriptHash()

        let message1 = Data([0x01, 0x02, 0x03])
        let message2 = Data([0x04, 0x05, 0x06])

        transcriptHash.update(with: message1)
        let hash1 = transcriptHash.currentHash()

        transcriptHash.update(with: message2)
        let hash2 = transcriptHash.currentHash()

        #expect(hash1 != hash2)
        #expect(hash1.count == 32) // SHA-256
        #expect(hash2.count == 32)
    }

    @Test("TranscriptHash is deterministic")
    func transcriptHashDeterministic() throws {
        let messages = [
            Data([0x01, 0x02, 0x03]),
            Data([0x04, 0x05, 0x06]),
            Data([0x07, 0x08, 0x09])
        ]

        var hash1 = TranscriptHash()
        var hash2 = TranscriptHash()

        for message in messages {
            hash1.update(with: message)
            hash2.update(with: message)
        }

        #expect(hash1.currentHash() == hash2.currentHash())
    }

    @Test("Empty TranscriptHash produces known hash")
    func emptyTranscriptHash() throws {
        let transcriptHash = TranscriptHash()
        let hash = transcriptHash.currentHash()

        // SHA-256 of empty input
        let emptyHash = SHA256.hash(data: Data())
        #expect(hash == Data(emptyHash))
    }

    // MARK: - SHA-384 Key Schedule Tests

    @Test("SHA-384 key schedule derives 384-bit secrets")
    func testSHA384KeySchedule() throws {
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_256_gcm_sha384)

        // P-384 shared secret for SHA-384 cipher suite
        let privateKey = P384.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        let transcriptHash = Data(repeating: 0xAA, count: 48)

        let (clientSecret, serverSecret) = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        #expect(clientSecret.bitCount == 384)
        #expect(serverSecret.bitCount == 384)
    }

    @Test("Exporter master secret derivation")
    func testExporterMasterSecret() throws {
        var keySchedule = TLSKeySchedule()

        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let hsTranscript = Data(repeating: 0xAA, count: 32)

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hsTranscript
        )

        let appTranscript = Data(repeating: 0xBB, count: 32)
        _ = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscript)

        let exporterTranscript = Data(repeating: 0xCC, count: 32)
        let exporterSecret = try keySchedule.deriveExporterMasterSecret(
            transcriptHash: exporterTranscript
        )

        #expect(exporterSecret.bitCount == 256)
        // Verify it is non-zero
        let exporterData = exporterSecret.withUnsafeBytes { Data($0) }
        #expect(exporterData != Data(repeating: 0, count: 32))
    }

    @Test("Resumption master secret derivation")
    func testResumptionMasterSecret() throws {
        var keySchedule = TLSKeySchedule()

        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let hsTranscript = Data(repeating: 0xAA, count: 32)

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hsTranscript
        )

        let appTranscript = Data(repeating: 0xBB, count: 32)
        _ = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscript)

        let resumptionTranscript = Data(repeating: 0xDD, count: 32)
        let resumptionSecret = try keySchedule.deriveResumptionMasterSecret(
            transcriptHash: resumptionTranscript
        )

        #expect(resumptionSecret.bitCount == 256)
        let resumptionData = resumptionSecret.withUnsafeBytes { Data($0) }
        #expect(resumptionData != Data(repeating: 0, count: 32))
    }

    @Test("Binder key derivation from PSK")
    func testBinderKeyDerivation() throws {
        var keySchedule = TLSKeySchedule()

        let psk = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        keySchedule.deriveEarlySecret(psk: psk)

        let binderKey = try keySchedule.deriveBinderKey(isResumption: true)

        #expect(binderKey.bitCount == 256)
        let binderData = binderKey.withUnsafeBytes { Data($0) }
        #expect(binderData != Data(repeating: 0, count: 32))
    }

    @Test("Key schedule state error when skipping handshake secrets")
    func testKeyScheduleStateError() throws {
        var keySchedule = TLSKeySchedule()

        // Try to derive application secrets without first deriving handshake secrets
        let appTranscript = Data(repeating: 0xBB, count: 32)
        #expect(throws: TLSKeyScheduleError.self) {
            _ = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscript)
        }
    }

    @Test("Export keying material produces correct length")
    func testExportKeyingMaterial() throws {
        var keySchedule = TLSKeySchedule()

        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let hsTranscript = Data(repeating: 0xAA, count: 32)

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hsTranscript
        )

        let appTranscript = Data(repeating: 0xBB, count: 32)
        _ = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscript)

        let exporterTranscript = Data(repeating: 0xCC, count: 32)
        let exporterSecret = try keySchedule.deriveExporterMasterSecret(
            transcriptHash: exporterTranscript
        )

        let desiredLength = 64
        let ekm = keySchedule.exportKeyingMaterial(
            exporterMasterSecret: exporterSecret,
            label: "test-label",
            context: Data("test-context".utf8),
            length: desiredLength
        )

        #expect(ekm.count == desiredLength)
        #expect(ekm != Data(repeating: 0, count: desiredLength))
    }
}
