/// Mutual TLS (mTLS) Tests
///
/// Tests the TLS 1.3 mutual authentication flow where both client and server
/// present certificates. Covers:
/// - Full mTLS handshake completion
/// - Server receiving client certificates
/// - CertificateRequest context echoing
/// - Empty certificate rejection when client auth is required
/// - Custom certificate validator integration
/// - Default behavior without requireClientCertificate
/// - PSK handshake skipping CertificateRequest
/// - Signature algorithms from CertificateRequest

import Testing
import Foundation
import Crypto
@preconcurrency import X509
import SwiftASN1

@testable import TLSCore

@Suite("Mutual TLS Tests", .serialized)
struct MutualTLSTests {

    // MARK: - Helpers

    /// Generates a self-signed X.509 certificate and returns the DER-encoded data
    /// along with a SigningKey backed by the same P-256 private key.
    ///
    /// The server's `processClientCertificate` unconditionally parses certificates
    /// with `X509Certificate.parse(from:)`, so we must provide valid DER data.
    private static func generateClientCertificate() throws -> (certDER: Data, signingKey: SigningKey) {
        let privateKey = P256.Signing.PrivateKey()

        let subject = try DistinguishedName {
            CommonName("mTLS Test Client")
            OrganizationName("Test")
        }

        let extensions = try X509.Certificate.Extensions {
            BasicConstraints.notCertificateAuthority
            KeyUsage(digitalSignature: true)
        }

        let certificate = try X509.Certificate(
            version: .v3,
            serialNumber: X509.Certificate.SerialNumber(),
            publicKey: X509.Certificate.PublicKey(privateKey.publicKey),
            notValidBefore: Date().addingTimeInterval(-3600),
            notValidAfter: Date().addingTimeInterval(3600),
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: X509.Certificate.PrivateKey(privateKey)
        )

        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        let derData = Data(serializer.serializedBytes)

        let signingKey = SigningKey.p256(privateKey)
        return (derData, signingKey)
    }

    /// Creates a client configuration for mTLS with a valid self-signed certificate.
    private static func mtlsClientConfig() throws -> (config: TLSConfiguration, signingKey: SigningKey) {
        let (certDER, clientKey) = try generateClientCertificate()

        var config = TLSConfiguration.client(serverName: "localhost")
        config.expectedPeerPublicKey = TestFixture.serverSigningKey.publicKeyBytes
        config.signingKey = clientKey
        config.certificateChain = [certDER]
        return (config, clientKey)
    }

    /// Creates a server configuration with requireClientCertificate enabled.
    ///
    /// X.509 chain validation for the client certificate is skipped by
    /// setting `verifyPeer = false`, since test certificates are self-signed
    /// without a trusted root. The TLS-level CertificateVerify signature is
    /// still validated via the public key extracted from the client's certificate.
    private static func mtlsServerConfig() -> TLSConfiguration {
        var config = TestFixture.serverConfig()
        config.requireClientCertificate = true
        config.verifyPeer = false
        return config
    }

    /// Performs a full mTLS handshake where the server processes the combined
    /// client Certificate + CertificateVerify + Finished messages.
    private func performMTLSHandshake(
        clientConfig: TLSConfiguration,
        serverConfig: TLSConfiguration
    ) async throws -> HandshakeResult {
        let client = TLS13Handler(configuration: clientConfig)
        let server = TLS13Handler(configuration: serverConfig)

        // Step 1: Client starts handshake
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

        // Step 4: Server processes client's response
        // In mTLS, this is Certificate + CertificateVerify + Finished combined
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

    // MARK: - Tests

    @Test("mTLS handshake completes successfully")
    func testMTLSHandshakeCompletes() async throws {
        let (clientConfig, _) = try MutualTLSTests.mtlsClientConfig()
        let serverConfig = MutualTLSTests.mtlsServerConfig()

        let result = try await performMTLSHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
        #expect(result.clientHandler.isClient == true)
        #expect(result.serverHandler.isClient == false)
    }

    @Test("mTLS server receives client certificate")
    func testMTLSServerReceivesClientCertificate() async throws {
        let (clientConfig, _) = try MutualTLSTests.mtlsClientConfig()
        let serverConfig = MutualTLSTests.mtlsServerConfig()

        let result = try await performMTLSHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        // Server should have received the client's certificates
        let peerCerts = result.serverHandler.peerCertificates
        #expect(peerCerts != nil)
        if let certs = peerCerts {
            #expect(!certs.isEmpty)
            // Verify the certificate is valid DER data that can be parsed
            let parsed = try X509Certificate.parse(from: certs[0])
            let cn = parsed.subject.commonName
            #expect(cn != nil)
            #expect(cn?.contains("mTLS Test Client") == true)
        }
    }

    @Test("CertificateRequest context echoed by client")
    func testCertificateRequestContextEchoed() async throws {
        // The CertificateRequest context must be echoed in the client's Certificate.
        // If the context does not match, the server throws invalidExtension during
        // processClientCertificate (line 1219 of TLS13Handler.swift).
        // A successful mTLS handshake proves the context was correctly echoed.
        let (clientConfig, _) = try MutualTLSTests.mtlsClientConfig()
        let serverConfig = MutualTLSTests.mtlsServerConfig()

        let result = try await performMTLSHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        // A successful handshake completion proves the certificate_request_context
        // was correctly echoed, since the server validates it in processClientCertificate.
        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)
    }

    @Test("Empty certificate rejected when client auth required")
    func testEmptyCertificateRejectedWhenRequired() async throws {
        // Client without signing key will send empty certificate
        var clientConfig = TLSConfiguration.client(serverName: "localhost")
        clientConfig.expectedPeerPublicKey = TestFixture.serverSigningKey.publicKeyBytes
        // No signingKey or certificateChain set -- client will send empty Certificate

        let serverConfig = MutualTLSTests.mtlsServerConfig()

        // The server should reject the empty certificate with certificateRequired
        await #expect(throws: TLSHandshakeError.self) {
            _ = try await performMTLSHandshake(
                clientConfig: clientConfig,
                serverConfig: serverConfig
            )
        }
    }

    @Test("mTLS with custom certificate validator")
    func testMTLSWithCustomValidator() async throws {
        let (clientConfig, _) = try MutualTLSTests.mtlsClientConfig()
        var serverConfig = MutualTLSTests.mtlsServerConfig()

        // Configure custom validator that returns peer info
        serverConfig.certificateValidator = { certs in
            return "peer-validated"
        }

        let result = try await performMTLSHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        #expect(result.serverHandler.isHandshakeComplete)

        // The server's validatedPeerInfo should contain the value from the validator
        let peerInfo = result.serverHandler.validatedPeerInfo
        #expect(peerInfo != nil)
        if let info = peerInfo as? String {
            #expect(info == "peer-validated")
        }
    }

    @Test("Client certificate not requested by default")
    func testClientCertificateNotRequestedByDefault() async throws {
        // Standard handshake without requireClientCertificate
        let result = try await performFullHandshake()

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)

        // Server should not have client certificates when mTLS is not configured
        let peerCerts = result.serverHandler.peerCertificates
        #expect(peerCerts == nil)
    }

    @Test("PSK handshake skips CertificateRequest even with requireClientCertificate")
    func testPSKHandshakeSkipsCertificateRequest() async throws {
        // In a PSK handshake, the server should NOT send CertificateRequest
        // even if requireClientCertificate is true.
        // PSK implies a pre-established identity (RFC 8446 Section 4.3.2).
        //
        // ServerStateMachine.processClientHello only sends CertificateRequest when
        // `!state.context.pskUsed && self.configuration.requireClientCertificate`

        // Set up a SessionTicketStore with a pre-stored session
        let ticketStore = SessionTicketStore()
        let resumptionMasterSecret = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let storedSession = SessionTicketStore.StoredSession(
            resumptionMasterSecret: resumptionMasterSecret,
            cipherSuite: .tls_aes_128_gcm_sha256,
            lifetime: 86400,
            ticketAgeAdd: 0x12345678,
            maxEarlyDataSize: 0
        )

        let serverTicket = ticketStore.generateTicket(for: storedSession)

        // Derive PSK that matches what the server will compute
        let keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let psk = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: resumptionMasterSecret,
            ticketNonce: serverTicket.ticketNonce
        )

        let sessionTicketData = SessionTicketData(
            ticket: serverTicket.ticket,
            resumptionPSK: psk,
            maxEarlyDataSize: 0,
            ticketAgeAdd: serverTicket.ticketAgeAdd,
            receiveTime: Date(),
            lifetime: serverTicket.ticketLifetime,
            cipherSuite: .tls_aes_128_gcm_sha256,
            serverName: "localhost",
            alpn: nil
        )

        // Server config: requireClientCertificate + sessionTicketStore
        var serverConfig = TLSConfiguration.server(
            signingKey: TestFixture.serverSigningKey,
            certificateChain: TestFixture.serverCertChain,
            sessionTicketStore: ticketStore
        )
        serverConfig.requireClientCertificate = true
        serverConfig.verifyPeer = false

        let clientConfig = TestFixture.clientConfig()

        let client = TLS13Handler(configuration: clientConfig)
        let server = TLS13Handler(configuration: serverConfig)

        try client.configureResumption(ticket: sessionTicketData, attemptEarlyData: false)

        // Perform PSK handshake
        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        var clientHelloData: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, _) = output {
                clientHelloData = data
            }
        }
        let clientHello = try #require(clientHelloData)

        let serverOutputs = try await server.processHandshakeData(clientHello, at: .initial)

        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        // Complete the handshake
        var clientFinishedData: Data?
        for (msgData, level) in serverMessages {
            let outputs = try await client.processHandshakeData(msgData, at: level)
            for output in outputs {
                if case .handshakeData(let data, _) = output {
                    clientFinishedData = data
                }
            }
        }

        if let finished = clientFinishedData {
            _ = try await server.processHandshakeData(finished, at: .handshake)
        }

        #expect(client.isHandshakeComplete)
        #expect(server.isHandshakeComplete)

        // Verify PSK was actually used
        #expect(server.pskUsed, "Server should have used PSK authentication")

        // In PSK mode, server should NOT have requested/received client certificates
        // even though requireClientCertificate is true
        let peerCerts = server.peerCertificates
        #expect(peerCerts == nil, "PSK handshake should skip CertificateRequest")
    }

    @Test("mTLS signature algorithms stored from CertificateRequest")
    func testMTLSSignatureAlgorithms() async throws {
        // Perform a full mTLS handshake and verify the handshake completes.
        // The CertificateRequest includes signature_algorithms, and the client
        // must use one of them for CertificateVerify. A successful handshake proves
        // the signature algorithms were correctly parsed and validated.
        let (clientConfig, clientKey) = try MutualTLSTests.mtlsClientConfig()
        let serverConfig = MutualTLSTests.mtlsServerConfig()

        let result = try await performMTLSHandshake(
            clientConfig: clientConfig,
            serverConfig: serverConfig
        )

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)

        // The client's signing key scheme must have been in the server's offered
        // signature algorithms from CertificateRequest. The handshake would have
        // failed with signatureVerificationFailed if not.
        // CertificateRequest.withDefaultSignatureAlgorithms() includes:
        //   ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ed25519, rsa_pss_*
        // Our client key is P-256 (ecdsa_secp256r1_sha256), which is in the list.
        #expect(clientKey.scheme == .ecdsa_secp256r1_sha256)
    }
}
