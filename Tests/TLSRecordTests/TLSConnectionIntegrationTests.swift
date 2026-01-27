/// TLS Connection Integration Tests
///
/// Tests the high-level TLSConnection API with complete handshake and
/// application data exchange. Verifies record layer framing and AEAD
/// encryption work correctly end-to-end.

import Testing
import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

@Suite("TLS Connection Integration Tests")
struct TLSConnectionIntegrationTests {

    // MARK: - Handshake

    @Test("Connection handshake completes")
    func connectionHandshakeCompletes() async throws {
        let (client, server) = try await performConnectionHandshake()

        #expect(client.isConnected)
        #expect(server.isConnected)
    }

    // MARK: - Application Data

    @Test("Connection exchanges application data")
    func connectionExchangesApplicationData() async throws {
        let (client, server) = try await performConnectionHandshake()

        // Client → Server
        let message = Data("Hello TLS 1.3".utf8)
        let encrypted = try client.writeApplicationData(message)
        let serverReceived = try await server.processReceivedData(encrypted)

        #expect(serverReceived.applicationData == message)

        // Server → Client
        let reply = Data("Hello back".utf8)
        let encryptedReply = try server.writeApplicationData(reply)
        let clientReceived = try await client.processReceivedData(encryptedReply)

        #expect(clientReceived.applicationData == reply)
    }

    @Test("Connection handles large data")
    func connectionHandlesLargeData() async throws {
        let (client, server) = try await performConnectionHandshake()

        // 32KB exceeds the 16KB max plaintext size, requiring fragmentation
        let largeData = Data(repeating: 0x42, count: 32768)
        let encrypted = try client.writeApplicationData(largeData)

        // Encrypted data should be larger than plaintext (AEAD overhead + record headers)
        #expect(encrypted.count > largeData.count)

        let received = try await server.processReceivedData(encrypted)
        #expect(received.applicationData == largeData)
    }

    @Test("Connection exchanges empty data")
    func connectionExchangesEmptyData() async throws {
        let (client, server) = try await performConnectionHandshake()

        let emptyData = Data()
        let encrypted = try client.writeApplicationData(emptyData)
        let received = try await server.processReceivedData(encrypted)

        #expect(received.applicationData == emptyData)
    }

    @Test("Connection close_notify exchange")
    func connectionCloseNotifyExchange() async throws {
        let (client, server) = try await performConnectionHandshake()

        let closeData = try client.close()
        #expect(!closeData.isEmpty)

        let received = try await server.processReceivedData(closeData)
        #expect(received.alert != nil)
        #expect(received.alert?.alertDescription == .closeNotify)
    }

    @Test("Connection server to client data")
    func connectionServerToClientData() async throws {
        let (client, server) = try await performConnectionHandshake()

        // Verify server → client direction (tests key direction mapping)
        let serverMessage = Data("Server says hello".utf8)
        let encrypted = try server.writeApplicationData(serverMessage)
        let clientReceived = try await client.processReceivedData(encrypted)

        #expect(clientReceived.applicationData == serverMessage)
    }

    @Test("Connection multiple messages")
    func connectionMultipleMessages() async throws {
        let (client, server) = try await performConnectionHandshake()

        // Send 10 messages to verify sequence numbers advance correctly
        for i in 0..<10 {
            let message = Data("Message \(i)".utf8)
            let encrypted = try client.writeApplicationData(message)
            let received = try await server.processReceivedData(encrypted)
            #expect(received.applicationData == message)
        }

        // Also verify reverse direction
        for i in 0..<10 {
            let message = Data("Reply \(i)".utf8)
            let encrypted = try server.writeApplicationData(message)
            let received = try await client.processReceivedData(encrypted)
            #expect(received.applicationData == message)
        }
    }
}
