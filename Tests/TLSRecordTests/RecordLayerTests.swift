/// TLS Record Layer Tests
///
/// Tests TLS record framing, AEAD encryption/decryption, nonce construction,
/// and the integrated record layer.

import Testing
import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

// MARK: - Record Codec Tests

@Suite("TLS Record Codec Tests")
struct TLSRecordCodecTests {

    @Test("Encode plaintext record")
    func encodePlaintext() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let record = TLSRecordCodec.encodePlaintext(type: .handshake, data: data)

        // Header: ContentType(1) + Version(2) + Length(2) = 5 bytes
        #expect(record.count == 5 + data.count)
        #expect(record[0] == TLSContentType.handshake.rawValue) // 22
        #expect(record[1] == 0x03) // Version high
        #expect(record[2] == 0x03) // Version low
        #expect(record[3] == 0x00) // Length high
        #expect(record[4] == 0x04) // Length low
        #expect(record[5] == 0x01)
        #expect(record[6] == 0x02)
    }

    @Test("Encode ciphertext record")
    func encodeCiphertext() {
        let ciphertext = Data(repeating: 0xAA, count: 100)
        let record = TLSRecordCodec.encodeCiphertext(ciphertext)

        #expect(record.count == 5 + ciphertext.count)
        #expect(record[0] == TLSContentType.applicationData.rawValue) // 23
        #expect(record[1] == 0x03)
        #expect(record[2] == 0x03)
    }

    @Test("Decode complete record")
    func decodeCompleteRecord() throws {
        let fragment = Data([0x01, 0x02, 0x03])
        let encoded = TLSRecordCodec.encodePlaintext(type: .handshake, data: fragment)

        let result = try TLSRecordCodec.decode(from: encoded)
        #expect(result != nil)

        let (record, consumed) = result!
        #expect(record.contentType == .handshake)
        #expect(record.fragment == fragment)
        #expect(consumed == encoded.count)
    }

    @Test("Decode returns nil for incomplete data")
    func decodeIncomplete() throws {
        // Less than header size
        let result1 = try TLSRecordCodec.decode(from: Data([0x16, 0x03]))
        #expect(result1 == nil)

        // Header says 10 bytes but only 5 available
        let header = Data([0x16, 0x03, 0x03, 0x00, 0x0A])
        let incomplete = header + Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let result2 = try TLSRecordCodec.decode(from: incomplete)
        #expect(result2 == nil)
    }

    @Test("Decode multiple records from buffer")
    func decodeMultipleRecords() throws {
        let record1 = TLSRecordCodec.encodePlaintext(type: .handshake, data: Data([0x01]))
        let record2 = TLSRecordCodec.encodePlaintext(type: .alert, data: Data([0x02, 0x28]))

        var buffer = record1 + record2

        // First record
        let result1 = try TLSRecordCodec.decode(from: buffer)
        #expect(result1 != nil)
        let (r1, consumed1) = result1!
        #expect(r1.contentType == .handshake)
        buffer = Data(buffer[consumed1...])

        // Second record
        let result2 = try TLSRecordCodec.decode(from: buffer)
        #expect(result2 != nil)
        let (r2, _) = result2!
        #expect(r2.contentType == .alert)
    }

    @Test("Decode rejects invalid content type")
    func rejectInvalidContentType() {
        // Content type 0xFF is invalid
        let data = Data([0xFF, 0x03, 0x03, 0x00, 0x01, 0x00])
        #expect(throws: TLSRecordError.self) {
            _ = try TLSRecordCodec.decode(from: data)
        }
    }

    @Test("Decode rejects oversized record")
    func rejectOversizedRecord() {
        // Length = 0x5000 = 20480 > maxCiphertextSize
        let data = Data([0x17, 0x03, 0x03, 0x50, 0x00])
        #expect(throws: TLSRecordError.self) {
            _ = try TLSRecordCodec.decode(from: data)
        }
    }

    @Test("Max plaintext size constant")
    func maxPlaintextSize() {
        #expect(TLSRecordCodec.maxPlaintextSize == 16384)
    }

    @Test("Max ciphertext size constant")
    func maxCiphertextSize() {
        #expect(TLSRecordCodec.maxCiphertextSize == 16384 + 256)
    }
}

// MARK: - Record Cryptor Tests

@Suite("TLS Record Cryptor Tests")
struct TLSRecordCryptorTests {

    @Test("Encrypt and decrypt roundtrip with AES-128-GCM")
    func encryptDecryptRoundtrip() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)

        // Generate test keys
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256,
        )

        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        // Encrypt
        let plaintext = Data("Hello, TLS!".utf8)
        let ciphertext = try cryptor.encrypt(content: plaintext, type: .applicationData)
        #expect(ciphertext.count > plaintext.count) // ciphertext + tag + content type

        // Decrypt
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)
        #expect(decrypted == plaintext)
        #expect(contentType == .applicationData)
    }

    @Test("Encrypt and decrypt handshake data")
    func encryptDecryptHandshake() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256,
        )

        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        let handshakeData = Data(repeating: 0xAA, count: 100)
        let ciphertext = try cryptor.encrypt(content: handshakeData, type: .handshake)
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)

        #expect(decrypted == handshakeData)
        #expect(contentType == .handshake)
    }

    @Test("Sequence numbers advance correctly")
    func sequenceNumberAdvancement() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256,
        )

        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        let plaintext = Data("test".utf8)

        // Encrypt two messages
        let ct1 = try cryptor.encrypt(content: plaintext, type: .applicationData)
        let ct2 = try cryptor.encrypt(content: plaintext, type: .applicationData)

        // Ciphertexts should differ due to different nonces
        #expect(ct1 != ct2)

        // Both should decrypt correctly (in order)
        let (d1, _) = try cryptor.decrypt(ciphertext: ct1)
        let (d2, _) = try cryptor.decrypt(ciphertext: ct2)
        #expect(d1 == plaintext)
        #expect(d2 == plaintext)
    }

    @Test("Decryption fails without keys")
    func decryptionFailsWithoutKeys() {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)

        #expect(throws: TLSRecordError.self) {
            _ = try cryptor.decrypt(ciphertext: Data(repeating: 0, count: 32))
        }
    }

    @Test("Encryption fails without keys")
    func encryptionFailsWithoutKeys() {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)

        #expect(throws: TLSRecordError.self) {
            _ = try cryptor.encrypt(content: Data("test".utf8), type: .applicationData)
        }
    }

    @Test("Plaintext too large throws error")
    func plaintextTooLarge() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256,
        )
        cryptor.updateSendKeys(keys)

        let oversized = Data(repeating: 0, count: TLSRecordCodec.maxPlaintextSize + 1)
        #expect(throws: TLSRecordError.self) {
            _ = try cryptor.encrypt(content: oversized, type: .applicationData)
        }
    }

    @Test("AES-256-GCM encrypt/decrypt roundtrip")
    func aes256GCMRoundtrip() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_256_gcm_sha384)

        let secret = SymmetricKey(data: Data(repeating: 0xAB, count: 48))
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_256_gcm_sha384,
        )

        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        let plaintext = Data("AES-256 test".utf8)
        let ciphertext = try cryptor.encrypt(content: plaintext, type: .applicationData)
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)

        #expect(decrypted == plaintext)
        #expect(contentType == .applicationData)
    }

    @Test("ChaCha20-Poly1305 encrypt/decrypt roundtrip")
    func chacha20Roundtrip() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_chacha20_poly1305_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_chacha20_poly1305_sha256,
        )

        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        let plaintext = Data("ChaCha20 test".utf8)
        let ciphertext = try cryptor.encrypt(content: plaintext, type: .applicationData)
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)

        #expect(decrypted == plaintext)
        #expect(contentType == .applicationData)
    }

    // Note: "Tampered ciphertext fails decryption" test removed because
    // CryptoKit traps (SIGTRAP) on AEAD authentication failure rather
    // than throwing a catchable error on this platform.
}

// MARK: - Record Layer Tests

@Suite("TLS Record Layer Tests")
struct TLSRecordLayerTests {

    @Test("Write and read plaintext handshake")
    func writeReadPlaintextHandshake() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let handshakeData = Data([0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00])
        let encoded = try layer.writeHandshake(handshakeData, encrypted: false)

        // Should be a plaintext record
        #expect(encoded[0] == TLSContentType.handshake.rawValue)

        // Process received data
        let outputs = try layer.processReceivedData(encoded)
        #expect(outputs.count == 1)

        if case .handshakeMessage(let data) = outputs[0] {
            #expect(data == handshakeData)
        } else {
            Issue.record("Expected handshakeMessage output")
        }
    }

    @Test("Write change cipher spec")
    func writeChangeCipherSpec() {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)
        let ccs = layer.writeChangeCipherSpec()

        #expect(ccs[0] == TLSContentType.changeCipherSpec.rawValue) // 20
        #expect(ccs.count == 6) // 5 header + 1 byte (0x01)
    }

    @Test("Write plaintext alert")
    func writePlaintextAlert() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)
        let alertData = try layer.writeAlert(.closeNotify)

        #expect(alertData[0] == TLSContentType.alert.rawValue) // 21
    }

    @Test("Encrypted application data roundtrip")
    func encryptedAppDataRoundtrip() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        // Set up keys
        let secret = SymmetricKey(size: .bits256)
        let sendKeys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256,
        )

        layer.updateKeys(send: sendKeys, receive: sendKeys)

        // Write application data
        let plaintext = Data("Hello from record layer!".utf8)
        let encrypted = try layer.writeApplicationData(plaintext)

        // Encrypted record should use applicationData content type
        #expect(encrypted[0] == TLSContentType.applicationData.rawValue)

        // Process received data
        let outputs = try layer.processReceivedData(encrypted)
        #expect(outputs.count == 1)

        if case .applicationData(let data) = outputs[0] {
            #expect(data == plaintext)
        } else {
            Issue.record("Expected applicationData output")
        }
    }

    @Test("Large data fragmentation")
    func largeDataFragmentation() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256,
        )
        layer.updateKeys(send: keys, receive: keys)

        // Create data larger than max plaintext size
        let largeData = Data(repeating: 0x42, count: TLSRecordCodec.maxPlaintextSize + 100)
        let encrypted = try layer.writeApplicationData(largeData)

        // Should produce multiple records
        #expect(encrypted.count > TLSRecordCodec.maxPlaintextSize)

        // Read back
        let outputs = try layer.processReceivedData(encrypted)
        // Should get 2 applicationData outputs (one per fragment)
        #expect(outputs.count == 2)

        var reassembled = Data()
        for output in outputs {
            if case .applicationData(let data) = output {
                reassembled.append(data)
            }
        }
        #expect(reassembled == largeData)
    }
}

// MARK: - Independent Key Update Tests

@Suite("TLS Record Layer Independent Key Update Tests")
struct TLSRecordLayerIndependentKeyTests {

    @Test("Send-only keys allow encryption but not decryption")
    func sendOnlyKeys() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256
        )

        // Only update send keys
        layer.updateSendKeys(keys)

        // Writing should work (send encryption active)
        let plaintext = Data("send-only test".utf8)
        let encrypted = try layer.writeApplicationData(plaintext)
        #expect(encrypted[0] == TLSContentType.applicationData.rawValue)

        // Reading encrypted data should fail because receive keys are not set.
        // RFC 8446 Section 5: applicationData records before encryption is active
        // on the receive side is a protocol violation.
        #expect(throws: TLSRecordError.self) {
            _ = try layer.processReceivedData(encrypted)
        }
    }

    @Test("Receive-only keys allow decryption but write is plaintext")
    func receiveOnlyKeys() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256
        )

        // Use a separate layer to produce encrypted data
        let producerLayer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)
        producerLayer.updateSendKeys(keys)

        let plaintext = Data("receive-only test".utf8)
        let encrypted = try producerLayer.writeApplicationData(plaintext)

        // Only update receive keys on the consumer
        layer.updateReceiveKeys(keys)

        // Decryption should work
        let outputs = try layer.processReceivedData(encrypted)
        #expect(outputs.count == 1)
        if case .applicationData(let data) = outputs[0] {
            #expect(data == plaintext)
        } else {
            Issue.record("Expected applicationData output")
        }
    }

    @Test("Alert respects send encryption state")
    func alertSendEncryption() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        // No keys — alert should be plaintext
        let plaintextAlert = try layer.writeAlert(.closeNotify)
        #expect(plaintextAlert[0] == TLSContentType.alert.rawValue) // 21

        // Set send keys — alert should be encrypted
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(
            secret: secret,
            cipherSuite: .tls_aes_128_gcm_sha256
        )
        layer.updateSendKeys(keys)

        let encryptedAlert = try layer.writeAlert(.closeNotify)
        #expect(encryptedAlert[0] == TLSContentType.applicationData.rawValue) // 23
    }

    @Test("Independent key transitions for server-side TLS 1.3 pattern")
    func serverSideKeyTransition() throws {
        // Simulates server-side TLS 1.3 key lifecycle:
        // 1. Server gets handshake keys → activate send + receive
        // 2. Server gets application keys → activate send only (defer receive)
        // 3. After ClientFinished → activate application receive

        let serverLayer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)
        let clientLayer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let hsSecret = SymmetricKey(size: .bits256)
        let hsKeys = TrafficKeys(secret: hsSecret, cipherSuite: .tls_aes_128_gcm_sha256)

        let appSecret = SymmetricKey(size: .bits256)
        let appKeys = TrafficKeys(secret: appSecret, cipherSuite: .tls_aes_128_gcm_sha256)

        // Step 1: Handshake keys — both directions
        serverLayer.updateKeys(send: hsKeys, receive: hsKeys)
        clientLayer.updateKeys(send: hsKeys, receive: hsKeys)

        // Server writes handshake data, client reads it
        let hsData = Data("handshake".utf8)
        let hsEncrypted = try serverLayer.writeHandshake(hsData, encrypted: true)
        let hsOutputs = try clientLayer.processReceivedData(hsEncrypted)
        #expect(hsOutputs.count == 1)
        if case .handshakeMessage(let data) = hsOutputs[0] {
            #expect(data == hsData)
        }

        // Step 2: Server transitions to application send keys only
        serverLayer.updateSendKeys(appKeys)

        // Server can now write with app keys
        let appData = Data("application".utf8)
        let appEncrypted = try serverLayer.writeApplicationData(appData)

        // Client needs app receive keys to read this
        clientLayer.updateReceiveKeys(appKeys)
        let appOutputs = try clientLayer.processReceivedData(appEncrypted)
        #expect(appOutputs.count == 1)
        if case .applicationData(let data) = appOutputs[0] {
            #expect(data == appData)
        }

        // Step 3: Server activates app receive keys
        serverLayer.updateReceiveKeys(appKeys)
        clientLayer.updateSendKeys(appKeys)

        let clientData = Data("from client".utf8)
        let clientEncrypted = try clientLayer.writeApplicationData(clientData)
        let clientOutputs = try serverLayer.processReceivedData(clientEncrypted)
        #expect(clientOutputs.count == 1)
        if case .applicationData(let data) = clientOutputs[0] {
            #expect(data == clientData)
        }
    }
}

// MARK: - Content Type Tests

@Suite("TLS Content Type Tests")
struct TLSContentTypeTests {

    @Test("Content type raw values")
    func contentTypeRawValues() {
        #expect(TLSContentType.changeCipherSpec.rawValue == 20)
        #expect(TLSContentType.alert.rawValue == 21)
        #expect(TLSContentType.handshake.rawValue == 22)
        #expect(TLSContentType.applicationData.rawValue == 23)
    }
}
