/// X25519MLKEM768 Hybrid Key Exchange Tests (draft-ietf-tls-ecdhe-mlkem)

import Testing
import TLSWireCore
import Foundation
import Crypto
@testable import TLSCore

@Suite("X25519MLKEM768 Key Exchange Tests")
struct X25519MLKEM768Tests {

    // MARK: - Client Share Generation

    @Test("Generate hybrid client share")
    func generateClientShare() throws {
        let keyExchange = try KeyExchange.generate(for: .x25519MLKEM768)

        #expect(keyExchange.group == .x25519MLKEM768)
        // ML-KEM-768 encapsulation key (1184) || X25519 public key (32)
        #expect(keyExchange.publicKeyBytes.count == 1216)
    }

    @Test("Hybrid KeyShareEntry")
    func hybridKeyShareEntry() throws {
        let keyExchange = try KeyExchange.generate(for: .x25519MLKEM768)
        let entry = keyExchange.keyShareEntry()

        #expect(entry.group == .x25519MLKEM768)
        #expect(entry.keyExchange == keyExchange.publicKeyBytes)
    }

    // MARK: - Server Response

    @Test("Server respond produces correct share and secret sizes")
    func serverRespond() throws {
        let client = try KeyExchange.generate(for: .x25519MLKEM768)

        let (ourShare, secret) = try KeyExchange.respond(
            group: .x25519MLKEM768,
            peerShare: client.publicKeyBytes
        )

        // ML-KEM-768 ciphertext (1088) || X25519 public key (32)
        #expect(ourShare.count == 1120)
        // ML-KEM-768 shared secret (32) || X25519 shared secret (32)
        #expect(secret.rawRepresentation.count == 64)
    }

    @Test("Client and server derive the same shared secret")
    func sharedSecretAgreement() throws {
        let client = try KeyExchange.generate(for: .x25519MLKEM768)

        let (serverShare, serverSecret) = try KeyExchange.respond(
            group: .x25519MLKEM768,
            peerShare: client.publicKeyBytes
        )
        let clientSecret = try client.sharedSecret(with: serverShare)

        #expect(clientSecret.rawRepresentation == serverSecret.rawRepresentation)
        #expect(clientSecret.rawRepresentation.count == 64)
    }

    @Test("Each encapsulation produces a distinct secret")
    func encapsulationsAreUnique() throws {
        let client = try KeyExchange.generate(for: .x25519MLKEM768)

        let (_, secret1) = try KeyExchange.respond(
            group: .x25519MLKEM768,
            peerShare: client.publicKeyBytes
        )
        let (_, secret2) = try KeyExchange.respond(
            group: .x25519MLKEM768,
            peerShare: client.publicKeyBytes
        )

        #expect(secret1.rawRepresentation != secret2.rawRepresentation)
    }

    @Test("Static performKeyAgreement supports the hybrid group")
    func performKeyAgreementHybrid() throws {
        let client = try KeyExchange.generate(for: .x25519MLKEM768)

        let (sharedSecret, ourPublicKey) = try KeyExchange.performKeyAgreement(
            group: .x25519MLKEM768,
            peerPublicKeyBytes: client.publicKeyBytes
        )
        let clientSecret = try client.sharedSecret(with: ourPublicKey)

        #expect(sharedSecret.rawRepresentation == clientSecret.rawRepresentation)
    }

    // MARK: - Error Cases

    @Test("Respond rejects wrong-size client share")
    func invalidClientShareSize() throws {
        #expect(throws: KeyExchangeError.self) {
            _ = try KeyExchange.respond(
                group: .x25519MLKEM768,
                peerShare: Data(repeating: 0x42, count: 100)
            )
        }
    }

    @Test("Client rejects wrong-size server share")
    func invalidServerShareSize() throws {
        let client = try KeyExchange.generate(for: .x25519MLKEM768)

        #expect(throws: KeyExchangeError.self) {
            _ = try client.sharedSecret(with: Data(repeating: 0x42, count: 32))
        }
    }

    @Test("Respond rejects malformed encapsulation key")
    func malformedEncapsulationKey() throws {
        // 0xFF-filled bytes fail the FIPS 203 modulus check: every decoded
        // coefficient is 4095, above the field modulus q = 3329.
        #expect(throws: KeyExchangeError.self) {
            _ = try KeyExchange.respond(
                group: .x25519MLKEM768,
                peerShare: Data(repeating: 0xFF, count: 1216)
            )
        }
    }

    // MARK: - Default Configuration (mirrors apple/swift-tls)

    @Test("Server factory accepts the hybrid group by default")
    func serverFactoryDefaultGroups() {
        let config = TLSConfiguration.server(
            signingKey: SigningKey.generateP256(),
            certificateChain: []
        )
        #expect(config.supportedGroups == [.x25519MLKEM768, .x25519, .secp256r1])
        #expect(config.supportedGroups == TLSConfiguration.defaultServerGroups)
    }

    @Test("Client factory defaults to classical groups")
    func clientFactoryDefaultGroups() {
        let config = TLSConfiguration.client(serverName: "localhost")
        #expect(config.supportedGroups == [.x25519, .secp256r1])
    }

    @Test("Hybrid-only client completes handshake against default server")
    func hybridClientAgainstDefaultServer() async throws {
        // The client offers ONLY the hybrid group, so handshake completion
        // proves the default server configuration negotiated X25519MLKEM768.
        var clientConfig = TestFixture.clientConfig()
        clientConfig.supportedGroups = [.x25519MLKEM768]

        let result = try await performFullHandshake(
            clientConfig: clientConfig,
            serverConfig: TestFixture.serverConfig()
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
    }

    // MARK: - End-to-End Handshake

    @Test("Full TLS 1.3 handshake over X25519MLKEM768")
    func hybridHandshake() async throws {
        var clientConfig = TestFixture.clientConfig()
        clientConfig.supportedGroups = [.x25519MLKEM768]
        var serverConfig = TestFixture.serverConfig()
        serverConfig.supportedGroups = [.x25519MLKEM768]

        let result = try await performFullHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        #expect(result.clientHandshakeKeys != nil)
        #expect(result.clientAppKeys != nil)
        #expect(result.serverHandshakeKeys != nil)
        #expect(result.serverAppKeys != nil)
    }
}
