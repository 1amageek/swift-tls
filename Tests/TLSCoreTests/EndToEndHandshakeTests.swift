/// End-to-End Handshake Tests
///
/// Tests the complete TLS 1.3 handshake at the TLS13Handler level.
/// Verifies that client and server can complete the full handshake,
/// derive consistent keys, negotiate ALPN, and exchange transport parameters.

import Testing
import Foundation
import Crypto

@testable import TLSCore

@Suite("End-to-End Handshake Tests")
struct EndToEndHandshakeTests {

    // MARK: - Full Handshake

    @Test("Full handshake completes successfully")
    func fullHandshakeCompletesSuccessfully() async throws {
        let result = try await performFullHandshake()

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        #expect(result.clientHandler.isClient == true)
        #expect(result.serverHandler.isClient == false)
    }

    @Test("Handshake keys are consistent")
    func handshakeKeysAreConsistent() async throws {
        let result = try await performFullHandshake()

        // Both sides should have handshake keys
        let serverHK = try #require(result.serverHandshakeKeys)
        let clientHK = try #require(result.clientHandshakeKeys)

        // Handshake-level secrets must match
        let serverClientSecret = try #require(serverHK.clientSecret)
        let serverServerSecret = try #require(serverHK.serverSecret)
        let clientClientSecret = try #require(clientHK.clientSecret)
        let clientServerSecret = try #require(clientHK.serverSecret)

        #expect(serverClientSecret == clientClientSecret)
        #expect(serverServerSecret == clientServerSecret)

        // Both sides should have application keys
        let serverAK = try #require(result.serverAppKeys)
        let clientAK = try #require(result.clientAppKeys)

        let sAppClient = try #require(serverAK.clientSecret)
        let sAppServer = try #require(serverAK.serverSecret)
        let cAppClient = try #require(clientAK.clientSecret)
        let cAppServer = try #require(clientAK.serverSecret)

        #expect(sAppClient == cAppClient)
        #expect(sAppServer == cAppServer)

        // Cipher suites must match
        #expect(serverHK.cipherSuite == clientHK.cipherSuite)
        #expect(serverAK.cipherSuite == clientAK.cipherSuite)
    }

    @Test("Handshake exchanges transport parameters")
    func handshakeExchangesTransportParameters() async throws {
        let clientParams = Data([0x04, 0x04, 0x00, 0x01, 0x00, 0x00])
        let serverParams = Data([0x04, 0x04, 0x00, 0x02, 0x00, 0x00])

        let client = TLS13Handler(configuration: TestFixture.clientConfig())
        let server = TLS13Handler(configuration: TestFixture.serverConfig())

        try client.setLocalTransportParameters(clientParams)
        try server.setLocalTransportParameters(serverParams)

        // Execute handshake
        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        var clientHelloData: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, _) = output {
                clientHelloData = data
            }
        }

        let serverOutputs = try await server.processHandshakeData(clientHelloData!, at: .initial)

        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        var clientFinished: Data?
        for (msg, level) in serverMessages {
            let outputs = try await client.processHandshakeData(msg, at: level)
            for output in outputs {
                if case .handshakeData(let data, _) = output {
                    clientFinished = data
                }
            }
        }

        if let finished = clientFinished {
            _ = try await server.processHandshakeData(finished, at: .handshake)
        }

        // Verify transport parameters were exchanged
        #expect(server.getPeerTransportParameters() == clientParams)
        #expect(client.getPeerTransportParameters() == serverParams)
    }

    @Test("Handshake negotiates ALPN")
    func handshakeNegotiatesALPN() async throws {
        let clientConfig = TestFixture.clientConfigWithALPN(["h3", "h2"])
        let serverConfig = TestFixture.serverConfigWithALPN(["h2"])

        let result = try await performFullHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        #expect(result.clientHandler.negotiatedALPN == "h2")
        #expect(result.serverHandler.negotiatedALPN == "h2")
    }

    @Test("Handshake without ALPN succeeds")
    func handshakeWithoutALPNSucceeds() async throws {
        let result = try await performFullHandshake()

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        // No ALPN negotiated when neither side offers
        // (client config has empty ALPN by default)
    }

    @Test("Exporter keying material matches both sides")
    func exporterKeyingMaterialMatchesBothSides() async throws {
        let result = try await performFullHandshake()

        let label = "test-exporter"
        let context = Data("test-context".utf8)
        let length = 32

        let clientExport = try result.clientHandler.exportKeyingMaterial(
            label: label,
            context: context,
            length: length
        )

        let serverExport = try result.serverHandler.exportKeyingMaterial(
            label: label,
            context: context,
            length: length
        )

        #expect(clientExport == serverExport)
        #expect(clientExport.count == length)
    }
}
