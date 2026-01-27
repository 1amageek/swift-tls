/// Invalid State Transition Tests
///
/// Tests that invalid or out-of-order handshake messages are properly rejected.
/// Verifies the TLS state machine enforces correct message ordering.

import Testing
import Foundation
import Crypto

@testable import TLSCore

@Suite("Invalid State Transition Tests")
struct InvalidStateTransitionTests {

    // MARK: - Encryption Level Validation

    @Test("Client rejects Certificate before ServerHello")
    func clientRejectsCertificateBeforeServerHello() async throws {
        let client = TLS13Handler(configuration: TestFixture.clientConfig())
        _ = try await client.startHandshake(isClient: true)

        // Fabricate a Certificate message
        let fakeCert = Certificate(certificates: [Data([0x30, 0x82, 0x01, 0x00])])
        let certMessage = fakeCert.encodeAsHandshake()

        // Client expects ServerHello at .initial level, not Certificate at .handshake
        await #expect(throws: Error.self) {
            _ = try await client.processHandshakeData(certMessage, at: .handshake)
        }
    }

    @Test("Client rejects EncryptedExtensions at initial level")
    func clientRejectsEncryptedExtensionsAtInitialLevel() async throws {
        let client = TLS13Handler(configuration: TestFixture.clientConfig())
        _ = try await client.startHandshake(isClient: true)

        // EncryptedExtensions must be at .handshake level, not .initial
        let ee = EncryptedExtensions(extensions: [])
        let eeMessage = ee.encodeAsHandshake()

        await #expect(throws: Error.self) {
            _ = try await client.processHandshakeData(eeMessage, at: .initial)
        }
    }

    @Test("Server rejects Finished before ClientHello")
    func serverRejectsFinishedBeforeClientHello() async throws {
        let server = TLS13Handler(configuration: TestFixture.serverConfig())
        _ = try await server.startHandshake(isClient: false)

        // Server expects ClientHello, not Finished
        let fakeFinished = Finished(verifyData: Data(repeating: 0xAA, count: 32))
        let finishedMessage = fakeFinished.encodeAsHandshake()

        await #expect(throws: Error.self) {
            _ = try await server.processHandshakeData(finishedMessage, at: .handshake)
        }
    }

    @Test("Wrong encryption level rejected")
    func wrongEncryptionLevelRejected() async throws {
        let client = TLS13Handler(configuration: TestFixture.clientConfig())
        _ = try await client.startHandshake(isClient: true)

        // ServerHello should be at .initial, not .handshake
        // Create a minimal ServerHello-like handshake message
        let fakeServerHello = HandshakeCodec.encode(
            type: .serverHello,
            content: Data(repeating: 0x00, count: 100)
        )

        await #expect(throws: Error.self) {
            _ = try await client.processHandshakeData(fakeServerHello, at: .handshake)
        }
    }

    // MARK: - Finished Verification

    @Test("Finished verification fails with corrupted data")
    func finishedVerificationFailsWithCorruptedData() async throws {
        let client = TLS13Handler(configuration: TestFixture.clientConfig())
        let server = TLS13Handler(configuration: TestFixture.serverConfig())

        // Start handshake
        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        var clientHelloData: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, _) = output {
                clientHelloData = data
            }
        }

        // Server processes ClientHello
        let serverOutputs = try await server.processHandshakeData(clientHelloData!, at: .initial)

        // Separate server messages
        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        // Process all messages except the last one (Finished)
        guard serverMessages.count >= 2 else {
            Issue.record("Server should produce multiple messages")
            return
        }

        // Process all messages up to (but not including) the last one (Finished)
        let finishedIndex = serverMessages.count - 1
        for i in 0..<finishedIndex {
            let (msg, level) = serverMessages[i]
            _ = try await client.processHandshakeData(msg, at: level)
        }

        // Corrupt the Finished message's verify_data
        var (corruptedFinished, finishedLevel) = serverMessages[finishedIndex]
        // The Finished message format: type(1) + length(3) + verify_data(32)
        // Corrupt the last byte of verify_data
        if corruptedFinished.count > 4 {
            corruptedFinished[corruptedFinished.count - 1] ^= 0xFF
        }

        await #expect(throws: TLSHandshakeError.self) {
            _ = try await client.processHandshakeData(corruptedFinished, at: finishedLevel)
        }
    }

}
