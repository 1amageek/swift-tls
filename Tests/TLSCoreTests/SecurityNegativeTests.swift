/// Security Negative Tests
///
/// Tests malformed, invalid, or attack-like inputs that must be rejected.
/// Verifies the TLS implementation correctly refuses truncated messages,
/// empty fields, missing extensions, corrupted data, and protocol violations.

import Testing
import Foundation
import Crypto

@testable import TLSCore
@testable import TLSRecord

@Suite("Security Negative Tests")
struct SecurityNegativeTests {

    // MARK: - 1. Truncated ClientHello

    @Test("Truncated ClientHello is rejected")
    func testTruncatedClientHello() throws {
        // A ClientHello with only 5 bytes is far too short to contain
        // even the legacy_version (2) + random (32)
        let truncatedData = Data([0x03, 0x03, 0x00, 0x01, 0x02])

        #expect(throws: Error.self) {
            _ = try ClientHello.decode(from: truncatedData)
        }
    }

    // MARK: - 2. Empty Cipher Suite List

    @Test("Empty cipher suite list is rejected")
    func testEmptyCipherSuiteList() throws {
        var writer = TLSWriter(capacity: 128)

        // legacy_version
        writer.writeUInt16(TLSConstants.legacyVersion)

        // random (32 bytes)
        writer.writeBytes(Data(repeating: 0xAA, count: TLSConstants.randomLength))

        // legacy_session_id (empty)
        writer.writeVector8(Data())

        // cipher_suites with zero length
        writer.writeUInt16(0x0000)

        // legacy_compression_methods
        writer.writeVector8(Data([0x00]))

        // extensions (empty but valid)
        writer.writeVector16(Data())

        let data = writer.finish()

        #expect(throws: Error.self) {
            _ = try ClientHello.decode(from: data)
        }
    }

    // MARK: - 3. Missing supported_versions Extension

    @Test("Missing supported_versions extension causes unsupportedVersion error")
    func testMissingSupportedVersionsExtension() throws {
        // Build a ClientHello without supported_versions extension
        let keyExchange = try KeyExchange.generate(for: .x25519)

        let clientHello = ClientHello(
            random: Data(repeating: 0xBB, count: TLSConstants.randomLength),
            legacySessionID: Data(),
            cipherSuites: [.tls_aes_128_gcm_sha256],
            extensions: [
                // Include key_share and supported_groups but NOT supported_versions
                .supportedGroupsList([.x25519]),
                .signatureAlgorithmsList([.ecdsa_secp256r1_sha256]),
                .keyShareClient([keyExchange.keyShareEntry()])
            ]
        )

        let clientHelloContent = clientHello.encode()

        let signingKey = SigningKey.generateP256()
        let config = TLSConfiguration.server(
            signingKey: signingKey,
            certificateChain: [Data([0x30, 0x82, 0x01, 0x00])]
        )
        let server = ServerStateMachine(configuration: config)

        #expect {
            _ = try server.processClientHello(clientHelloContent)
        } throws: { error in
            if let handshakeError = error as? TLSHandshakeError {
                return handshakeError == .unsupportedVersion
            }
            return false
        }
    }

    // MARK: - 4. HelloRetryRequest Sentinel Random Detection

    @Test("ServerHello with HRR sentinel random is detected as HelloRetryRequest")
    func testInvalidServerHelloRandom() throws {
        // SHA-256 of "HelloRetryRequest" is the HRR sentinel
        let hrrRandom = TLSConstants.helloRetryRequestRandom

        let serverHello = ServerHello(
            random: hrrRandom,
            legacySessionIDEcho: Data(),
            cipherSuite: .tls_aes_128_gcm_sha256,
            extensions: [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShare(.helloRetryRequest(KeyShareHelloRetryRequest(selectedGroup: .x25519)))
            ]
        )

        #expect(serverHello.isHelloRetryRequest == true)

        // Verify that a normal ServerHello is NOT detected as HRR
        let normalServerHello = ServerHello(
            random: Data(repeating: 0x42, count: TLSConstants.randomLength),
            legacySessionIDEcho: Data(),
            cipherSuite: .tls_aes_128_gcm_sha256,
            extensions: []
        )
        #expect(normalServerHello.isHelloRetryRequest == false)
    }

    // MARK: - 5. Corrupted Finished Verify Data

    @Test("Corrupted Finished verify data is rejected")
    func testCorruptedFinishedVerifyData() async throws {
        let clientConfig = TestFixture.clientConfig()
        let serverConfig = TestFixture.serverConfig()

        let client = TLS13Handler(configuration: clientConfig)
        let server = TLS13Handler(configuration: serverConfig)

        // Start handshake
        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        var clientHelloData: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, _) = output {
                clientHelloData = data
            }
        }
        let clientHello = try #require(clientHelloData)

        // Server processes ClientHello
        let serverOutputs = try await server.processHandshakeData(clientHello, at: .initial)

        // Separate server messages by type
        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        // Process all messages except the last one (which contains Finished)
        let lastIndex = serverMessages.count - 1
        #expect(lastIndex >= 1, "Server should produce at least 2 message groups")

        for i in 0..<lastIndex {
            let (msg, level) = serverMessages[i]
            _ = try await client.processHandshakeData(msg, at: level)
        }

        // Corrupt the Finished message's verify_data
        var (corruptedFinished, finishedLevel) = serverMessages[lastIndex]
        // The Finished message: type(1) + length(3) + verify_data(32)
        // Flip a bit in verify_data
        if corruptedFinished.count > 4 {
            corruptedFinished[corruptedFinished.count - 1] ^= 0xFF
        }

        await #expect(throws: TLSHandshakeError.self) {
            _ = try await client.processHandshakeData(corruptedFinished, at: finishedLevel)
        }
    }

    // MARK: - 6. Invalid Cipher Suite in ServerHello

    @Test("ServerHello with cipher suite not offered by client is rejected")
    func testInvalidCipherSuiteInServerHello() async throws {
        // Client offers only AES-128-GCM
        var clientConfig = TLSConfiguration.client(serverName: "localhost")
        clientConfig.expectedPeerPublicKey = TestFixture.serverSigningKey.publicKeyBytes
        clientConfig.supportedCipherSuites = [.tls_aes_128_gcm_sha256]

        let clientMachine = ClientStateMachine()
        let (_, _) = try clientMachine.startHandshake(
            configuration: clientConfig,
            transportParameters: nil
        )

        // Craft a ServerHello with AES-256-GCM (not offered by client)
        let keyExchange = try KeyExchange.generate(for: .x25519)
        let serverHello = ServerHello(
            legacySessionIDEcho: Data(),
            cipherSuite: .tls_aes_256_gcm_sha384,
            extensions: [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShareServer(keyExchange.keyShareEntry())
            ]
        )
        let serverHelloContent = serverHello.encode()

        #expect {
            _ = try clientMachine.processServerHello(serverHelloContent)
        } throws: { error in
            if let handshakeError = error as? TLSHandshakeError {
                return handshakeError == .noCipherSuiteMatch
            }
            return false
        }
    }

    // MARK: - 7. Key Update Before Handshake Completes

    @Test("Key update before handshake completes is rejected")
    func testKeyUpdateBeforeHandshake() async throws {
        let client = TLS13Handler(configuration: TestFixture.clientConfig())
        _ = try await client.startHandshake(isClient: true)

        // Handshake is not complete yet
        #expect(client.isHandshakeComplete == false)

        await #expect(throws: Error.self) {
            _ = try await client.requestKeyUpdate()
        }
    }

    // MARK: - 8. NewSessionTicket to Server

    @Test("Server receiving NewSessionTicket rejects as unexpected message")
    func testNewSessionTicketToServer() async throws {
        let server = TLS13Handler(configuration: TestFixture.serverConfig())
        _ = try await server.startHandshake(isClient: false)

        // Fabricate a NewSessionTicket message
        var writer = TLSWriter(capacity: 64)
        writer.writeUInt32(3600)         // ticket_lifetime
        writer.writeUInt32(0x12345678)   // ticket_age_add
        writer.writeVector8(Data([0x01, 0x02])) // ticket_nonce
        writer.writeVector16(Data(repeating: 0xAA, count: 16)) // ticket
        writer.writeVector16(Data())     // extensions

        let ticketContent = writer.finish()
        let ticketMessage = HandshakeCodec.encode(type: .newSessionTicket, content: ticketContent)

        // Server should reject this - NewSessionTicket at .application level
        // but server hasn't completed handshake, and even if it had,
        // a server should not receive NewSessionTicket
        await #expect(throws: Error.self) {
            _ = try await server.processHandshakeData(ticketMessage, at: .application)
        }
    }

    // MARK: - 9. Empty Extension Data

    @Test("Extension with zero-length data can be parsed or rejected")
    func testEmptyExtensionData() throws {
        // Build raw extension bytes: type(2) + length(2, value 0) + no data
        var writer = TLSWriter(capacity: 4)
        // Use supported_groups extension type
        writer.writeUInt16(TLSExtensionType.supportedGroups.rawValue)
        writer.writeUInt16(0x0000) // zero-length data

        let extensionBytes = writer.finish()
        var reader = TLSReader(data: extensionBytes)

        // This should either parse (returning empty data) or throw a decode error.
        // The supported_groups extension parser will expect at least 2 bytes for the list length.
        #expect(throws: Error.self) {
            _ = try TLSExtension.decode(from: &reader)
        }
    }

    // MARK: - 10. Duplicate Extensions

    @Test("Duplicate extensions in ClientHello are rejected")
    func testDuplicateExtensionsRejected() throws {
        // Build a ClientHello with duplicate supported_versions extensions.
        // RFC 8446 Section 4.2: "There MUST NOT be more than one extension
        // of the same type in a given extension block."
        let keyExchange = try KeyExchange.generate(for: .x25519)

        let clientHello = ClientHello(
            random: Data(repeating: 0xCC, count: TLSConstants.randomLength),
            legacySessionID: Data(),
            cipherSuites: [.tls_aes_128_gcm_sha256],
            extensions: [
                .supportedVersionsClient([TLSConstants.version13]),
                .supportedGroupsList([.x25519]),
                .signatureAlgorithmsList([.ecdsa_secp256r1_sha256]),
                .keyShareClient([keyExchange.keyShareEntry()]),
                // Duplicate supported_versions — must be rejected
                .supportedVersionsClient([TLSConstants.version13])
            ]
        )

        let encoded = clientHello.encode()

        #expect(throws: TLSHandshakeError.self) {
            _ = try ClientHello.decode(from: encoded)
        }
    }

    // MARK: - 11. Invalid Content Type

    @Test("Invalid content type byte in TLS record is rejected")
    func testInvalidContentType() throws {
        // Build a TLS record with invalid content type 0xFF
        var record = Data(capacity: 10)
        record.append(0xFF)       // Invalid content type
        record.append(0x03)       // Version high
        record.append(0x03)       // Version low
        record.append(0x00)       // Length high
        record.append(0x05)       // Length low (5 bytes)
        record.append(contentsOf: [0x01, 0x02, 0x03, 0x04, 0x05]) // Fragment

        #expect {
            _ = try TLSRecordCodec.decode(from: record)
        } throws: { error in
            if let recordError = error as? TLSRecordError {
                if case .invalidContentType(let byte) = recordError {
                    return byte == 0xFF
                }
            }
            return false
        }
    }

    // MARK: - 12. Max Length Record

    @Test("Record at exact max plaintext size boundary")
    func testMaxLengthRecord() throws {
        let maxData = Data(repeating: 0xAB, count: TLSRecordCodec.maxPlaintextSize)

        // Encode as plaintext record
        let encoded = TLSRecordCodec.encodePlaintext(type: .applicationData, data: maxData)

        // Should decode successfully
        let result = try TLSRecordCodec.decode(from: encoded)
        let (record, bytesConsumed) = try #require(result)

        #expect(record.contentType == .applicationData)
        #expect(record.fragment == maxData)
        #expect(bytesConsumed == TLSRecordCodec.headerSize + TLSRecordCodec.maxPlaintextSize)

        // Now try one byte over the max ciphertext size
        let oversized = Data(repeating: 0xCD, count: TLSRecordCodec.maxCiphertextSize + 1)
        var oversizedRecord = Data(capacity: TLSRecordCodec.headerSize + oversized.count)
        oversizedRecord.append(TLSContentType.applicationData.rawValue)
        oversizedRecord.append(0x03)
        oversizedRecord.append(0x03)
        oversizedRecord.append(UInt8(oversized.count >> 8))
        oversizedRecord.append(UInt8(oversized.count & 0xFF))
        oversizedRecord.append(oversized)

        #expect(throws: TLSRecordError.self) {
            _ = try TLSRecordCodec.decode(from: oversizedRecord)
        }
    }

    // MARK: - 13. Zero Length Plaintext Through Cryptor

    @Test("Zero-length content encrypts and decrypts through TLSRecordCryptor")
    func testZeroLengthPlaintext() throws {
        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)

        let cryptor = TLSRecordCryptor(cipherSuite: .tls_aes_128_gcm_sha256)
        cryptor.updateSendKeys(keys)
        cryptor.updateReceiveKeys(keys)

        // Encrypt zero-length content
        let emptyContent = Data()
        let ciphertext = try cryptor.encrypt(content: emptyContent, type: .applicationData)

        // Ciphertext should not be empty (it contains the content type byte + AEAD tag)
        #expect(ciphertext.count > 0)

        // Decrypt should recover empty content
        let (decrypted, contentType) = try cryptor.decrypt(ciphertext: ciphertext)
        #expect(decrypted == emptyContent)
        #expect(contentType == .applicationData)
    }
}
