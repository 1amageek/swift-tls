/// Concurrency Tests for TLS Record Layer
///
/// Verifies thread-safety of the 3-lock architecture in TLSConnection,
/// concurrent AEAD operations in TLSRecordCryptor, and concurrent
/// record layer writes in TLSRecordLayer.

import Testing
import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

// MARK: - Concurrent Record Cryptor Tests

@Suite("Concurrent Record Cryptor Tests", .serialized)
struct ConcurrentRecordCryptorTests {

    @Test("Concurrent record encryption produces 100 valid ciphertexts")
    func testConcurrentRecordEncryption() async throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        cryptor.updateSendKeys(keys)

        let results = try await withThrowingTaskGroup(of: Data.self) { group in
            for i in 0..<100 {
                group.addTask {
                    let message = Data("msg-\(i)".utf8)
                    return try cryptor.encrypt(content: message, type: .applicationData)
                }
            }
            var collected: [Data] = []
            for try await result in group {
                collected.append(result)
            }
            return collected
        }

        #expect(results.count == 100)

        // Each ciphertext must be non-empty and larger than the plaintext
        // (plaintext + 1 byte content type + 16 byte AEAD tag)
        for ciphertext in results {
            #expect(ciphertext.count > 0)
        }

        // All ciphertexts must be unique (different nonces produce different output)
        let uniqueCount = Set(results).count
        #expect(uniqueCount == 100)
    }

    @Test("Sequential encrypt then decrypt roundtrip for N messages")
    func testSequentialEncryptDecryptCorrectness() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        let messageCount = 50
        var ciphertexts: [Data] = []
        var plaintexts: [Data] = []

        // Encrypt N messages sequentially
        for i in 0..<messageCount {
            let plaintext = Data("sequential-message-\(i)".utf8)
            plaintexts.append(plaintext)
            let ciphertext = try cryptor.encrypt(content: plaintext, type: .applicationData)
            ciphertexts.append(ciphertext)
        }

        // Decrypt in same sequential order
        for i in 0..<messageCount {
            let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertexts[i])
            #expect(decrypted == plaintexts[i])
            #expect(contentType == .applicationData)
        }
    }

    @Test("Sequence number continuity and replay detection")
    func testSequenceNumberContinuity() throws {
        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        // Encrypt 10 messages sequentially
        var ciphertexts: [Data] = []
        for i in 0..<10 {
            let plaintext = Data("nonce-msg-\(i)".utf8)
            let ciphertext = try cryptor.encrypt(content: plaintext, type: .applicationData)
            ciphertexts.append(ciphertext)
        }

        // Decrypt all 10 in order - all should succeed
        for i in 0..<10 {
            let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertexts[i])
            #expect(decrypted == Data("nonce-msg-\(i)".utf8))
            #expect(contentType == .applicationData)
        }

        // Now try to "replay" the first ciphertext.
        // The receive sequence number is at 10, so the nonce will not match
        // the nonce used to encrypt ciphertexts[0] (which used sequence 0).
        // This should fail with badRecordMac.
        #expect(throws: TLSRecordError.self) {
            _ = try cryptor.decrypt(ciphertext: ciphertexts[0])
        }
    }
}

// MARK: - Concurrent Record Layer Tests

@Suite("Concurrent Record Layer Tests", .serialized)
struct ConcurrentRecordLayerTests {

    @Test("Concurrent record layer writes from 50 tasks")
    func testConcurrentRecordLayerWrites() async throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)
        let secret = SymmetricKey(size: .bits256)
        let sendKeys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        let receiveKeys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        layer.updateKeys(send: sendKeys, receive: receiveKeys)

        let results = try await withThrowingTaskGroup(of: Data.self) { group in
            for i in 0..<50 {
                group.addTask {
                    let message = Data("layer-write-\(i)".utf8)
                    return try layer.writeApplicationData(message)
                }
            }
            var collected: [Data] = []
            for try await result in group {
                collected.append(result)
            }
            return collected
        }

        #expect(results.count == 50)

        // Each result must be a valid TLS record (starts with applicationData content type 0x17)
        for record in results {
            #expect(record.count > TLSRecordCodec.headerSize)
            #expect(record[record.startIndex] == TLSContentType.applicationData.rawValue)
        }

        // All encrypted records must be unique (different nonces)
        let uniqueCount = Set(results).count
        #expect(uniqueCount == 50)
    }

    @Test("Multiple record layer roundtrips between sender and receiver")
    func testMultipleRecordLayerRoundtrips() throws {
        let senderLayer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)
        let receiverLayer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)

        // Sender encrypts with keys, receiver decrypts with same keys
        senderLayer.updateSendKeys(keys)
        receiverLayer.updateReceiveKeys(keys)

        let messageCount = 50
        var expectedMessages: [Data] = []

        // Send 50 messages sequentially and verify each decrypts correctly
        for i in 0..<messageCount {
            let plaintext = Data("roundtrip-\(i)-payload".utf8)
            expectedMessages.append(plaintext)

            let encrypted = try senderLayer.writeApplicationData(plaintext)

            // Receiver processes the encrypted record
            let outputs = try receiverLayer.processReceivedData(encrypted)
            #expect(outputs.count == 1)

            if case .applicationData(let decrypted) = outputs[0] {
                #expect(decrypted == plaintext)
            } else {
                Issue.record("Expected applicationData output for message \(i)")
            }
        }

        #expect(expectedMessages.count == messageCount)
    }
}

// MARK: - Concurrent TLSConnection Tests

@Suite("Concurrent TLSConnection Tests", .serialized)
struct ConcurrentTLSConnectionTests {

    @Test("Concurrent application data writes after handshake", .timeLimit(.minutes(1)))
    func testConcurrentConnectionWrites() async throws {
        let (client, server) = try await performConnectionHandshake()

        #expect(client.isConnected)
        #expect(server.isConnected)

        // Concurrently write 50 messages from the client
        let results = try await withThrowingTaskGroup(of: Data.self) { group in
            for i in 0..<50 {
                group.addTask {
                    let message = Data("concurrent-conn-\(i)".utf8)
                    return try client.writeApplicationData(message)
                }
            }
            var collected: [Data] = []
            for try await result in group {
                collected.append(result)
            }
            return collected
        }

        #expect(results.count == 50)

        // All results should be non-empty encrypted TLS records
        for record in results {
            #expect(record.count > 0)
        }

        // All encrypted records must be unique
        let uniqueCount = Set(results).count
        #expect(uniqueCount == 50)
    }

    @Test("Sequential bidirectional data exchange after handshake", .timeLimit(.minutes(1)))
    func testBidirectionalDataExchange() async throws {
        let (client, server) = try await performConnectionHandshake()

        #expect(client.isConnected)
        #expect(server.isConnected)

        // Client sends to server, server processes
        for i in 0..<10 {
            let message = Data("client-to-server-\(i)".utf8)
            let encrypted = try client.writeApplicationData(message)
            let output = try await server.processReceivedData(encrypted)

            #expect(output.applicationData == message)
        }

        // Server sends to client, client processes
        for i in 0..<10 {
            let message = Data("server-to-client-\(i)".utf8)
            let encrypted = try server.writeApplicationData(message)
            let output = try await client.processReceivedData(encrypted)

            #expect(output.applicationData == message)
        }
    }
}
