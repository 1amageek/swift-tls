/// Transport-Agnostic TLS Tests
///
/// Tests that TLS handshake works without transport parameters and without ALPN.

import Testing
import Foundation

@testable import TLSCore

@Suite("Transport Agnostic Tests")
struct TransportAgnosticTests {

    private static let testSigningKey = SigningKey.generateP256()
    private static let testCertificateChain = [Data([0x30, 0x82, 0x01, 0x00])]

    // MARK: - No Transport Parameters

    @Test("Client handshake without transport parameters")
    func clientHandshakeWithoutTransportParams() async throws {
        let config = TLSConfiguration.client(serverName: "localhost")
        let handler = TLS13Handler(configuration: config)

        // Start handshake WITHOUT setting transport parameters
        let outputs = try await handler.startHandshake(isClient: true)

        #expect(handler.isClient == true)
        #expect(!outputs.isEmpty, "Should have ClientHello output")

        // Verify ClientHello was generated
        guard case .handshakeData(let data, let level) = outputs[0] else {
            Issue.record("Expected handshakeData output")
            return
        }
        #expect(level == .initial)
        #expect(data[0] == 0x01) // ClientHello type

        // Decode and verify no transport parameters extension
        let (_, length) = try HandshakeCodec.decodeHeader(from: data)
        let content = data.subdata(in: 4..<(4 + length))
        let clientHello = try ClientHello.decode(from: content)
        #expect(clientHello.transportParameters == nil)
    }

    @Test("ClientStateMachine without transport parameters")
    func clientStateMachineWithoutTransportParams() throws {
        let config = TLSConfiguration.client(serverName: "localhost")
        let clientMachine = ClientStateMachine()

        // Start without transport parameters (nil)
        let (clientHelloData, _) = try clientMachine.startHandshake(
            configuration: config
        )

        #expect(clientMachine.handshakeState == .waitServerHello)
        #expect(clientHelloData[0] == 0x01) // ClientHello type

        // Verify no transport parameters in encoded message
        let (_, length) = try HandshakeCodec.decodeHeader(from: clientHelloData)
        let content = clientHelloData.subdata(in: 4..<(4 + length))
        let clientHello = try ClientHello.decode(from: content)
        #expect(clientHello.transportParameters == nil)
    }

    // MARK: - No ALPN

    @Test("Client handshake without ALPN")
    func clientHandshakeWithoutALPN() async throws {
        let config = TLSConfiguration.client(serverName: "localhost")
        // Default ALPN is now empty
        #expect(config.alpnProtocols.isEmpty)

        let handler = TLS13Handler(configuration: config)
        let outputs = try await handler.startHandshake(isClient: true)

        #expect(!outputs.isEmpty)
    }

    @Test("Server accepts client without ALPN")
    func serverAcceptsNoALPN() async throws {
        // Server with no ALPN configured
        var serverConfig = TLSConfiguration()
        serverConfig.signingKey = Self.testSigningKey
        serverConfig.certificateChain = Self.testCertificateChain
        let server = TLS13Handler(configuration: serverConfig)

        // Client with no ALPN
        var clientConfig = TLSConfiguration.client(serverName: "localhost")
        clientConfig.expectedPeerPublicKey = Self.testSigningKey.publicKeyBytes
        let client = TLS13Handler(configuration: clientConfig)

        // Client starts
        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        // Get ClientHello
        guard case .handshakeData(let clientHelloData, _) = clientOutputs[0] else {
            Issue.record("Expected handshakeData")
            return
        }

        // Server processes ClientHello - should succeed without ALPN
        let serverOutputs = try await server.processHandshakeData(clientHelloData, at: .initial)
        #expect(!serverOutputs.isEmpty, "Server should produce outputs")
    }

    @Test("Default configuration has empty ALPN")
    func defaultConfigEmptyALPN() {
        let config = TLSConfiguration()
        #expect(config.alpnProtocols.isEmpty)
    }

    @Test("Client factory has empty ALPN by default")
    func clientFactoryEmptyALPN() {
        let config = TLSConfiguration.client()
        #expect(config.alpnProtocols.isEmpty)
    }

    @Test("Server factory has empty ALPN by default")
    func serverFactoryEmptyALPN() {
        let config = TLSConfiguration.server(
            signingKey: Self.testSigningKey,
            certificateChain: Self.testCertificateChain
        )
        #expect(config.alpnProtocols.isEmpty)
    }

    // MARK: - With Transport Parameters (backward compatibility)

    @Test("Client with transport parameters still works")
    func clientWithTransportParams() async throws {
        let config = TLSConfiguration.client(serverName: "localhost")
        let handler = TLS13Handler(configuration: config)

        // Set transport parameters
        let params = Data([0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
        try handler.setLocalTransportParameters(params)

        let outputs = try await handler.startHandshake(isClient: true)
        #expect(!outputs.isEmpty)

        // Verify transport parameters are present in ClientHello
        guard case .handshakeData(let data, _) = outputs[0] else {
            Issue.record("Expected handshakeData")
            return
        }
        let (_, length) = try HandshakeCodec.decodeHeader(from: data)
        let content = data.subdata(in: 4..<(4 + length))
        let clientHello = try ClientHello.decode(from: content)
        #expect(clientHello.transportParameters != nil)
        #expect(clientHello.transportParameters == params)
    }

    // MARK: - With ALPN (backward compatibility)

    @Test("Explicit ALPN configuration works")
    func explicitALPNWorks() {
        let config = TLSConfiguration.client(alpnProtocols: ["h3", "h2"])
        #expect(config.alpnProtocols == ["h3", "h2"])
    }
}
