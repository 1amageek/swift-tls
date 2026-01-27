/// Shared Test Helpers for TLS Security Tests
///
/// Common fixtures, configurations, and helper functions used across
/// all TLS test files.

import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

// MARK: - Test Fixture

enum TestFixture {
    static let serverSigningKey = SigningKey.generateP256()
    static let serverCertChain: [Data] = [Data([0x30, 0x82, 0x01, 0x00])]

    static func clientConfig() -> TLSConfiguration {
        var config = TLSConfiguration.client(serverName: "localhost")
        config.expectedPeerPublicKey = serverSigningKey.publicKeyBytes
        return config
    }

    static func serverConfig() -> TLSConfiguration {
        .server(signingKey: serverSigningKey, certificateChain: serverCertChain)
    }

    static func clientConfigWithALPN(_ protocols: [String]) -> TLSConfiguration {
        var config = clientConfig()
        config.alpnProtocols = protocols
        return config
    }

    static func serverConfigWithALPN(_ protocols: [String]) -> TLSConfiguration {
        var config = serverConfig()
        config.alpnProtocols = protocols
        return config
    }
}

// MARK: - Handshake Result

/// Result of a complete TLS 1.3 handshake at the TLS13Handler level
struct HandshakeResult {
    let clientHandler: TLS13Handler
    let serverHandler: TLS13Handler
    let serverHandshakeKeys: KeysAvailableInfo?
    let serverAppKeys: KeysAvailableInfo?
    let clientHandshakeKeys: KeysAvailableInfo?
    let clientAppKeys: KeysAvailableInfo?
}

// MARK: - Test Error

enum TestError: Error {
    case missingData(String)
    case unexpectedOutput(String)
}

// MARK: - Full Handshake Helper

/// Performs a complete TLS 1.3 handshake between client and server TLS13Handlers.
///
/// Steps:
/// 1. Client starts → ClientHello
/// 2. Server starts (no output)
/// 3. Server processes ClientHello → SH + EE + Cert + CV + Finished + keys
/// 4. Client processes each server message at the correct encryption level
/// 5. Server processes client Finished
///
/// - Parameters:
///   - clientConfig: Client TLS configuration (defaults to TestFixture.clientConfig)
///   - serverConfig: Server TLS configuration (defaults to TestFixture.serverConfig)
/// - Returns: HandshakeResult with both handlers and extracted keys
func performFullHandshake(
    clientConfig: TLSConfiguration? = nil,
    serverConfig: TLSConfiguration? = nil
) async throws -> HandshakeResult {
    let cConfig = clientConfig ?? TestFixture.clientConfig()
    let sConfig = serverConfig ?? TestFixture.serverConfig()

    let client = TLS13Handler(configuration: cConfig)
    let server = TLS13Handler(configuration: sConfig)

    // Step 1: Client starts
    let clientOutputs = try await client.startHandshake(isClient: true)
    _ = try await server.startHandshake(isClient: false)

    // Extract ClientHello data
    var clientHelloData: Data?
    for output in clientOutputs {
        if case .handshakeData(let data, _) = output {
            clientHelloData = data
        }
    }
    guard let clientHello = clientHelloData else {
        throw TestError.missingData("ClientHello")
    }

    // Step 2: Server processes ClientHello
    let serverOutputs = try await server.processHandshakeData(clientHello, at: .initial)

    // Separate server outputs by type
    var serverHandshakeMessages: [(Data, TLSEncryptionLevel)] = []
    var serverHandshakeKeys: KeysAvailableInfo?
    var serverAppKeys: KeysAvailableInfo?

    for output in serverOutputs {
        switch output {
        case .handshakeData(let data, let level):
            serverHandshakeMessages.append((data, level))
        case .keysAvailable(let info):
            if info.level == .handshake {
                serverHandshakeKeys = info
            } else if info.level == .application {
                serverAppKeys = info
            }
        default: break
        }
    }

    // Step 3: Client processes server messages one by one
    var clientHandshakeKeys: KeysAvailableInfo?
    var clientAppKeys: KeysAvailableInfo?
    var clientFinishedData: Data?

    for (msgData, level) in serverHandshakeMessages {
        let outputs = try await client.processHandshakeData(msgData, at: level)
        for output in outputs {
            switch output {
            case .handshakeData(let data, _):
                clientFinishedData = data
            case .keysAvailable(let info):
                if info.level == .handshake {
                    clientHandshakeKeys = info
                } else if info.level == .application {
                    clientAppKeys = info
                }
            default: break
            }
        }
    }

    // Step 4: Server processes client Finished
    if let finished = clientFinishedData {
        _ = try await server.processHandshakeData(finished, at: .handshake)
    }

    return HandshakeResult(
        clientHandler: client,
        serverHandler: server,
        serverHandshakeKeys: serverHandshakeKeys,
        serverAppKeys: serverAppKeys,
        clientHandshakeKeys: clientHandshakeKeys,
        clientAppKeys: clientAppKeys
    )
}

/// Performs a complete TLS 1.3 handshake between two TLSConnection instances.
///
/// - Parameters:
///   - clientConfig: Client TLS configuration
///   - serverConfig: Server TLS configuration
/// - Returns: Tuple of (clientConnection, serverConnection) with handshake complete
func performConnectionHandshake(
    clientConfig: TLSConfiguration? = nil,
    serverConfig: TLSConfiguration? = nil
) async throws -> (client: TLSConnection, server: TLSConnection) {
    let cConfig = clientConfig ?? TestFixture.clientConfig()
    let sConfig = serverConfig ?? TestFixture.serverConfig()

    let client = TLSConnection(configuration: cConfig)
    let server = TLSConnection(configuration: sConfig)

    // Client sends ClientHello
    let clientHello = try await client.startHandshake(isClient: true)
    _ = try await server.startHandshake(isClient: false)

    // Server processes ClientHello → ServerHello + encrypted messages
    let serverResponse = try await server.processReceivedData(clientHello)

    // Client processes server response → ClientFinished
    let clientResponse = try await client.processReceivedData(serverResponse.dataToSend)

    // Server processes client Finished
    if !clientResponse.dataToSend.isEmpty {
        _ = try await server.processReceivedData(clientResponse.dataToSend)
    }

    return (client, server)
}
