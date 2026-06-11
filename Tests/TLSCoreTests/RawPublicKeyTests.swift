/// Raw Public Key Authentication Tests (RFC 7250)

import Testing
import Foundation
import Crypto
@testable import TLSCore

// MARK: - Certificate Type Extension Tests

@Suite("Certificate Type Extension Tests")
struct CertificateTypeExtensionTests {

    @Test("Offered list roundtrip in ClientHello context")
    func offeredRoundtrip() throws {
        let ext = TLSExtension.clientCertificateTypes([.rawPublicKey, .x509])
        let encoded = ext.encode()

        var reader = TLSReader(data: encoded)
        let decoded = try TLSExtension.decode(from: &reader)

        guard case .clientCertificateType(.offered(let types)) = decoded else {
            Issue.record("Expected offered client_certificate_type, got \(decoded)")
            return
        }
        #expect(types == [.rawPublicKey, .x509])
    }

    @Test("Selected type roundtrip in EncryptedExtensions context")
    func selectedRoundtrip() throws {
        let ext = TLSExtension.serverCertificateTypeSelected(.rawPublicKey)
        let encoded = ext.encode()

        var reader = TLSReader(data: encoded)
        let decoded = try TLSExtension.decode(from: &reader, context: .encryptedExtensions)

        guard case .serverCertificateType(.selected(let type)) = decoded else {
            Issue.record("Expected selected server_certificate_type, got \(decoded)")
            return
        }
        #expect(type == .rawPublicKey)
    }

    @Test("Unknown certificate types in offered list are ignored")
    func unknownOfferedTypesIgnored() throws {
        // List: raw_public_key (2), openpgp (1, unsupported)
        let body = Data([0x02, 0x02, 0x01])
        let decoded = try ClientCertificateTypeExtension.decodeOffered(from: body)

        #expect(decoded == .offered([.rawPublicKey]))
    }

    @Test("Empty offered list is rejected")
    func emptyOfferedListRejected() throws {
        #expect(throws: TLSDecodeError.self) {
            _ = try ServerCertificateTypeExtension.decodeOffered(from: Data([0x00]))
        }
    }

    @Test("Trailing bytes after offered list are rejected")
    func trailingBytesRejected() throws {
        #expect(throws: TLSDecodeError.self) {
            _ = try ClientCertificateTypeExtension.decodeOffered(from: Data([0x01, 0x00, 0xFF]))
        }
    }

    @Test("Unknown selected type is rejected")
    func unknownSelectedTypeRejected() throws {
        #expect(throws: TLSDecodeError.self) {
            _ = try ServerCertificateTypeExtension.decodeSelected(from: Data([0x07]))
        }
    }

    @Test("Multi-byte selected type is rejected")
    func multiByteSelectedRejected() throws {
        #expect(throws: TLSDecodeError.self) {
            _ = try ClientCertificateTypeExtension.decodeSelected(from: Data([0x00, 0x02]))
        }
    }

    @Test("ClientHello carries both certificate type extensions")
    func clientHelloAccessors() throws {
        let hello = try ClientHello(extensions: [
            .clientCertificateTypes([.rawPublicKey]),
            .serverCertificateTypes([.rawPublicKey, .x509])
        ])

        let decoded = try ClientHello.decode(from: hello.encode())

        #expect(decoded.clientCertificateTypes == [.rawPublicKey])
        #expect(decoded.serverCertificateTypes == [.rawPublicKey, .x509])
    }

    @Test("EncryptedExtensions carries selected certificate types")
    func encryptedExtensionsAccessors() throws {
        let ee = EncryptedExtensions(extensions: [
            .serverCertificateTypeSelected(.rawPublicKey),
            .clientCertificateTypeSelected(.x509)
        ])

        let decoded = try EncryptedExtensions.decode(from: ee.encode())

        #expect(decoded.selectedServerCertificateType == .rawPublicKey)
        #expect(decoded.selectedClientCertificateType == .x509)
    }
}

// MARK: - SubjectPublicKeyInfo Tests

@Suite("SubjectPublicKeyInfo Tests")
struct SubjectPublicKeyInfoTests {

    @Test("P-256 SPKI roundtrip")
    func p256Roundtrip() throws {
        let signingKey = SigningKey.generateP256()
        let der = try SubjectPublicKeyInfo.encode(signingKey: signingKey)

        let spki = try SubjectPublicKeyInfo.decode(from: der)

        #expect(spki.verificationKey.publicKeyBytes == signingKey.publicKeyBytes)
        #expect(spki.derRepresentation == der)

        // The decoded key must verify signatures from the original key.
        let message = Data("raw public key".utf8)
        let signature = try signingKey.sign(message)
        #expect(try spki.verificationKey.verify(signature: signature, for: message))
    }

    @Test("P-384 SPKI roundtrip")
    func p384Roundtrip() throws {
        let signingKey = SigningKey.generateP384()
        let der = try SubjectPublicKeyInfo.encode(signingKey: signingKey)

        let spki = try SubjectPublicKeyInfo.decode(from: der)

        #expect(spki.verificationKey.publicKeyBytes == signingKey.publicKeyBytes)

        let message = Data("raw public key".utf8)
        let signature = try signingKey.sign(message)
        #expect(try spki.verificationKey.verify(signature: signature, for: message))
    }

    @Test("Ed25519 SPKI roundtrip")
    func ed25519Roundtrip() throws {
        let signingKey = SigningKey.generateEd25519()
        let der = try SubjectPublicKeyInfo.encode(signingKey: signingKey)

        let spki = try SubjectPublicKeyInfo.decode(from: der)

        #expect(spki.verificationKey.publicKeyBytes == signingKey.publicKeyBytes)

        let message = Data("raw public key".utf8)
        let signature = try signingKey.sign(message)
        #expect(try spki.verificationKey.verify(signature: signature, for: message))
    }

    @Test("Unsupported scheme is rejected on encode")
    func unsupportedSchemeRejected() throws {
        #expect(throws: SignatureError.self) {
            _ = try SubjectPublicKeyInfo.encode(
                scheme: .rsa_pss_rsae_sha256,
                publicKeyBytes: Data(repeating: 0x01, count: 270)
            )
        }
    }

    @Test("Malformed DER is rejected on decode")
    func malformedDERRejected() throws {
        #expect(throws: SignatureError.self) {
            _ = try SubjectPublicKeyInfo.decode(from: Data([0x30, 0x02, 0x01, 0x00]))
        }
        #expect(throws: SignatureError.self) {
            _ = try SubjectPublicKeyInfo.decode(from: Data(repeating: 0xAB, count: 16))
        }
    }
}

// MARK: - Raw Public Key Handshake Tests

@Suite("Raw Public Key Handshake Tests", .serialized)
struct RawPublicKeyHandshakeTests {

    /// Builds a server configuration that authenticates with a raw public key only.
    private func rpkServerConfig(signingKey: SigningKey) -> TLSConfiguration {
        var config = TLSConfiguration.server(signingKey: signingKey, certificateChain: [])
        config.localCertificateTypes = [.rawPublicKey]
        return config
    }

    /// Builds a client configuration that accepts only raw public keys from the server.
    private func rpkClientConfig(trustedSPKI: Data) -> TLSConfiguration {
        var config = TLSConfiguration.client(serverName: "localhost")
        config.peerCertificateTypes = [.rawPublicKey]
        config.trustedRawPublicKeys = [trustedSPKI]
        return config
    }

    @Test("Server authentication with trusted raw public key")
    func serverAuthWithTrustedKey() async throws {
        let serverKey = SigningKey.generateP256()
        let serverSPKI = try SubjectPublicKeyInfo.encode(signingKey: serverKey)

        let result = try await performFullHandshake(
            clientConfig: rpkClientConfig(trustedSPKI: serverSPKI),
            serverConfig: rpkServerConfig(signingKey: serverKey)
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        #expect(result.clientHandler.peerCertificates == [serverSPKI])
    }

    @Test("Server authentication with expectedPeerPublicKey")
    func serverAuthWithExpectedPublicKey() async throws {
        let serverKey = SigningKey.generateP256()

        var clientConfig = TLSConfiguration.client(serverName: "localhost")
        clientConfig.peerCertificateTypes = [.rawPublicKey]
        clientConfig.expectedPeerPublicKey = serverKey.publicKeyBytes

        let result = try await performFullHandshake(
            clientConfig: clientConfig,
            serverConfig: rpkServerConfig(signingKey: serverKey)
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
    }

    @Test("Server authentication with Ed25519 raw public key")
    func serverAuthWithEd25519() async throws {
        let serverKey = SigningKey.generateEd25519()
        let serverSPKI = try SubjectPublicKeyInfo.encode(signingKey: serverKey)

        let result = try await performFullHandshake(
            clientConfig: rpkClientConfig(trustedSPKI: serverSPKI),
            serverConfig: rpkServerConfig(signingKey: serverKey)
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
    }

    @Test("Mutual authentication with raw public keys")
    func mutualRawPublicKeyAuth() async throws {
        let serverKey = SigningKey.generateP256()
        let serverSPKI = try SubjectPublicKeyInfo.encode(signingKey: serverKey)
        let clientKey = SigningKey.generateP256()
        let clientSPKI = try SubjectPublicKeyInfo.encode(signingKey: clientKey)

        var clientConfig = rpkClientConfig(trustedSPKI: serverSPKI)
        clientConfig.signingKey = clientKey
        clientConfig.localCertificateTypes = [.rawPublicKey]

        var serverConfig = rpkServerConfig(signingKey: serverKey)
        serverConfig.requireClientCertificate = true
        serverConfig.peerCertificateTypes = [.rawPublicKey]
        serverConfig.trustedRawPublicKeys = [clientSPKI]

        let result = try await performFullHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        #expect(result.clientHandler.peerCertificates == [serverSPKI])
        #expect(result.serverHandler.peerCertificates == [clientSPKI])
    }

    @Test("Untrusted raw public key is rejected")
    func untrustedKeyRejected() async throws {
        let serverKey = SigningKey.generateP256()
        let unrelatedKey = SigningKey.generateP256()
        let unrelatedSPKI = try SubjectPublicKeyInfo.encode(signingKey: unrelatedKey)

        await #expect(throws: TLSHandshakeError.self) {
            _ = try await performFullHandshake(
                clientConfig: rpkClientConfig(trustedSPKI: unrelatedSPKI),
                serverConfig: rpkServerConfig(signingKey: serverKey)
            )
        }
    }

    @Test("Negotiation falls back to X.509 when server prefers it")
    func negotiationFallsBackToX509() async throws {
        // Client accepts both types; server only does X.509.
        var clientConfig = TestFixture.clientConfig()
        clientConfig.peerCertificateTypes = [.rawPublicKey, .x509]

        let result = try await performFullHandshake(
            clientConfig: clientConfig,
            serverConfig: TestFixture.serverConfig()
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        #expect(result.clientHandler.peerCertificates == TestFixture.serverCertChain)
    }

    @Test("Server rejects when it cannot satisfy offered types")
    func serverRejectsUnsatisfiableOffer() async throws {
        // Client only accepts raw public keys; server only has X.509.
        let serverKey = SigningKey.generateP256()
        let serverSPKI = try SubjectPublicKeyInfo.encode(signingKey: serverKey)

        await #expect(throws: TLSHandshakeError.self) {
            _ = try await performFullHandshake(
                clientConfig: rpkClientConfig(trustedSPKI: serverSPKI),
                serverConfig: TestFixture.serverConfig()
            )
        }
    }
}
