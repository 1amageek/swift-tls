/// KeyUpdate End-to-End Tests
///
/// Tests TLS 1.3 KeyUpdate post-handshake message flow (RFC 8446 Section 4.6.3).
/// Verifies key rotation, peer response, bidirectional updates, and error handling.

import Testing
import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

@Suite("KeyUpdate End-to-End Tests")
struct KeyUpdateE2ETests {

    // MARK: - Single-Side Key Update

    @Test("Client requests key update after handshake")
    func testClientRequestsKeyUpdate() async throws {
        let result = try await performFullHandshake()

        let outputs = try await result.clientHandler.requestKeyUpdate()

        var hasHandshakeData = false
        var hasNewKeys = false

        for output in outputs {
            switch output {
            case .handshakeData(let data, let level):
                #expect(!data.isEmpty)
                #expect(level == .application)
                hasHandshakeData = true
            case .keysAvailable(let info):
                #expect(info.level == .application)
                #expect(info.clientSecret != nil, "Client send secret should be updated")
                #expect(info.serverSecret == nil, "Server receive secret should not change yet")
                hasNewKeys = true
            default:
                break
            }
        }

        #expect(hasHandshakeData, "KeyUpdate message should be emitted as handshake data")
        #expect(hasNewKeys, "New keys should be emitted after key update")
    }

    @Test("Server requests key update after handshake")
    func testServerRequestsKeyUpdate() async throws {
        let result = try await performFullHandshake()

        let outputs = try await result.serverHandler.requestKeyUpdate()

        var hasHandshakeData = false
        var hasNewKeys = false

        for output in outputs {
            switch output {
            case .handshakeData(let data, let level):
                #expect(!data.isEmpty)
                #expect(level == .application)
                hasHandshakeData = true
            case .keysAvailable(let info):
                #expect(info.level == .application)
                #expect(info.serverSecret != nil, "Server send secret should be updated")
                #expect(info.clientSecret == nil, "Client receive secret should not change yet")
                hasNewKeys = true
            default:
                break
            }
        }

        #expect(hasHandshakeData, "KeyUpdate message should be emitted as handshake data")
        #expect(hasNewKeys, "New keys should be emitted after key update")
    }

    // MARK: - Peer Response

    @Test("Peer produces KeyUpdate response when processing KeyUpdate")
    func testKeyUpdateResponseFromPeer() async throws {
        let result = try await performFullHandshake()

        // Client requests key update
        let clientOutputs = try await result.clientHandler.requestKeyUpdate()

        // Extract the KeyUpdate handshake message from client
        var keyUpdateMessage: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, let level) = output {
                #expect(level == .application)
                keyUpdateMessage = data
            }
        }
        let message = try #require(keyUpdateMessage, "Client should produce a KeyUpdate message")

        // Server processes the KeyUpdate message
        let serverOutputs = try await result.serverHandler.processHandshakeData(message, at: .application)

        var serverHasHandshakeData = false
        var serverRecvKeysUpdated = false
        var serverSendKeysUpdated = false

        for output in serverOutputs {
            switch output {
            case .handshakeData(let data, let level):
                #expect(!data.isEmpty)
                #expect(level == .application)
                serverHasHandshakeData = true
            case .keysAvailable(let info):
                #expect(info.level == .application)
                if info.clientSecret != nil {
                    // Server receives client's new send secret as its receive key
                    serverRecvKeysUpdated = true
                }
                if info.serverSecret != nil {
                    // Server also updates its own send key in response
                    serverSendKeysUpdated = true
                }
            default:
                break
            }
        }

        #expect(serverRecvKeysUpdated, "Server should update receive keys from peer's KeyUpdate")
        #expect(serverHasHandshakeData, "Server should respond with its own KeyUpdate message")
        #expect(serverSendKeysUpdated, "Server should update send keys in response to update_requested")
    }

    // MARK: - Bidirectional Key Update

    @Test("Both sides request key update and get new keys")
    func testBidirectionalKeyUpdate() async throws {
        let result = try await performFullHandshake()

        // Client requests key update
        let clientOutputs = try await result.clientHandler.requestKeyUpdate()
        var clientGotNewKeys = false
        for output in clientOutputs {
            if case .keysAvailable(let info) = output {
                #expect(info.level == .application)
                #expect(info.clientSecret != nil)
                clientGotNewKeys = true
            }
        }
        #expect(clientGotNewKeys, "Client should receive new keys after requesting key update")

        // Server requests key update independently
        let serverOutputs = try await result.serverHandler.requestKeyUpdate()
        var serverGotNewKeys = false
        for output in serverOutputs {
            if case .keysAvailable(let info) = output {
                #expect(info.level == .application)
                #expect(info.serverSecret != nil)
                serverGotNewKeys = true
            }
        }
        #expect(serverGotNewKeys, "Server should receive new keys after requesting key update")
    }

    // MARK: - Key Material Verification

    @Test("Keys after update differ from original keys")
    func testDataAfterKeyUpdate() async throws {
        let result = try await performFullHandshake()

        let originalClientAppKeys = try #require(result.clientAppKeys)
        let originalClientSecret = try #require(originalClientAppKeys.clientSecret)

        let outputs = try await result.clientHandler.requestKeyUpdate()

        var newClientSecret: SymmetricKey?
        for output in outputs {
            if case .keysAvailable(let info) = output {
                newClientSecret = info.clientSecret
            }
        }

        let updatedSecret = try #require(newClientSecret, "Key update should produce a new client secret")

        let originalData = originalClientSecret.withUnsafeBytes { Data($0) }
        let updatedData = updatedSecret.withUnsafeBytes { Data($0) }
        #expect(originalData != updatedData, "New keys must differ from original keys after key update")
    }

    // MARK: - Multiple Sequential Key Updates

    @Test("Multiple key updates toggle keyPhase correctly")
    func testMultipleKeyUpdates() async throws {
        let result = try await performFullHandshake()

        #expect(result.clientHandler.keyPhase == 0, "Initial keyPhase should be 0")

        // First key update: 0 -> 1
        _ = try await result.clientHandler.requestKeyUpdate()
        #expect(result.clientHandler.keyPhase == 1, "keyPhase should be 1 after first update")

        // Second key update: 1 -> 0
        _ = try await result.clientHandler.requestKeyUpdate()
        #expect(result.clientHandler.keyPhase == 0, "keyPhase should be 0 after second update")

        // Third key update: 0 -> 1
        _ = try await result.clientHandler.requestKeyUpdate()
        #expect(result.clientHandler.keyPhase == 1, "keyPhase should be 1 after third update")
    }

    // MARK: - Error Handling

    @Test("Key update before handshake complete is rejected")
    func testKeyUpdateBeforeHandshakeCompleteRejected() async throws {
        let config = TestFixture.clientConfig()
        let handler = TLS13Handler(configuration: config)

        // Start handshake but do not complete it
        _ = try await handler.startHandshake(isClient: true)

        // Attempting key update before handshake is complete should throw
        await #expect(throws: TLSError.self) {
            _ = try await handler.requestKeyUpdate()
        }
    }
}
