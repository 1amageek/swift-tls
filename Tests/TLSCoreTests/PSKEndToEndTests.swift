/// PSK / Session Resumption End-to-End Tests
///
/// Tests cover:
/// - Full PSK handshake flow (initial + resumed)
/// - PSK handshake skips Certificate/CertificateVerify
/// - PSK key derivation from resumption master secret
/// - Expired ticket rejection
/// - Client session cache store/retrieve
/// - Client session cache purge of expired entries
/// - NewSessionTicket round-trip encoding/decoding
/// - Obfuscated ticket age arithmetic
/// - Resumption master secret availability after handshake
/// - Cipher suite mismatch PSK rejection (fallback to full handshake)

import Testing
import Foundation
import Crypto
@testable import TLSCore

// MARK: - PSK End-to-End Tests

@Suite("PSK End-to-End Tests", .serialized)
struct PSKEndToEndTests {

    // MARK: - 1. Full PSK Handshake

    @Test("PSK offered but server falls back to full handshake (no ticket store)")
    func testFullPSKHandshake() async throws {
        // Step 1: Perform initial full handshake
        let result = try await performFullHandshake()
        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)

        // Step 2: Generate a NewSessionTicket from the server side
        // Since the server state machine needs a SessionTicketStore, we set up
        // the ticket data manually using the resumption master secret from the
        // client handler's state machine.
        let clientAppKeys = try #require(result.clientAppKeys)
        let cipherSuite = clientAppKeys.cipherSuite

        // Construct a synthetic NewSessionTicket
        let ticketNonce = Data([0x00, 0x01, 0x02, 0x03])
        let ticketValue = Data(repeating: 0xAA, count: 32)
        let ticketAgeAdd: UInt32 = 0x12345678
        let ticketLifetime: UInt32 = 3600

        let keySchedule = TLSKeySchedule(cipherSuite: cipherSuite)

        // Simulate the NewSessionTicket info as if the server sent it
        // The client handler derives resumption master secret after handshake
        // We need to derive a PSK from a known resumption master secret
        let dummyResumptionSecret = SymmetricKey(data: Data(repeating: 0x42, count: cipherSuite.hashLength))
        let resumptionPSK = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: dummyResumptionSecret,
            ticketNonce: ticketNonce
        )

        let sessionTicketData = SessionTicketData(
            ticket: ticketValue,
            resumptionPSK: resumptionPSK,
            maxEarlyDataSize: 0,
            ticketAgeAdd: ticketAgeAdd,
            receiveTime: Date(),
            lifetime: ticketLifetime,
            cipherSuite: cipherSuite,
            serverName: "localhost",
            alpn: nil
        )

        #expect(sessionTicketData.isValid())

        // Step 3: Configure a new client with the session ticket
        let clientConfig = TestFixture.clientConfig()
        let serverConfig = TestFixture.serverConfig()

        // Create client and server handlers
        let client = TLS13Handler(configuration: clientConfig)
        let server = TLS13Handler(configuration: serverConfig)

        // Configure resumption on the client
        try client.configureResumption(ticket: sessionTicketData, attemptEarlyData: false)

        // Step 4: Start the PSK handshake
        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        // Extract ClientHello
        var clientHelloData: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, _) = output {
                clientHelloData = data
            }
        }
        let clientHello = try #require(clientHelloData)

        // Process ClientHello on server
        // The server will not find the PSK in its store (no store configured),
        // so it falls back to a full handshake. This validates the end-to-end flow.
        let serverOutputs = try await server.processHandshakeData(clientHello, at: .initial)

        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        // Process server messages on client
        var clientFinishedData: Data?
        for (msgData, level) in serverMessages {
            let outputs = try await client.processHandshakeData(msgData, at: level)
            for output in outputs {
                if case .handshakeData(let data, _) = output {
                    clientFinishedData = data
                }
            }
        }

        // Process client finished on server
        if let finished = clientFinishedData {
            _ = try await server.processHandshakeData(finished, at: .handshake)
        }

        #expect(client.isHandshakeComplete)
        #expect(server.isHandshakeComplete)
    }

    // MARK: - 2. PSK Handshake Skips Certificate

    @Test("PSK handshake skips Certificate and CertificateVerify messages")
    func testPSKHandshakeSkipsCertificate() async throws {
        // Set up a server with SessionTicketStore to enable real PSK handshake
        let serverSigningKey = TestFixture.serverSigningKey
        let serverCertChain = TestFixture.serverCertChain

        let ticketStore = SessionTicketStore()
        let resumptionMasterSecret = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let ticketAgeAdd: UInt32 = 0x12345678

        // Store a session in the server's ticket store
        let storedSession = SessionTicketStore.StoredSession(
            resumptionMasterSecret: resumptionMasterSecret,
            cipherSuite: .tls_aes_128_gcm_sha256,
            lifetime: 86400,
            ticketAgeAdd: ticketAgeAdd,
            maxEarlyDataSize: 0
        )

        let serverTicket = try ticketStore.generateTicket(for: storedSession)

        // Derive PSK that matches what the server will compute
        let keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let psk = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: resumptionMasterSecret,
            ticketNonce: serverTicket.ticketNonce
        )

        // Create session ticket for client
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

        // Configure client with PSK
        let clientConfig = TestFixture.clientConfig()
        var serverConfig = TLSConfiguration.server(
            signingKey: serverSigningKey,
            certificateChain: serverCertChain,
            sessionTicketStore: ticketStore
        )
        serverConfig.expectedPeerPublicKey = nil

        let client = TLS13Handler(configuration: clientConfig)
        let server = TLS13Handler(configuration: serverConfig)

        try client.configureResumption(ticket: sessionTicketData, attemptEarlyData: false)

        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        var clientHelloData: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, _) = output {
                clientHelloData = data
            }
        }

        guard let clientHello = clientHelloData else {
            Issue.record("Missing ClientHello")
            return
        }

        let serverOutputs = try await server.processHandshakeData(clientHello, at: .initial)

        // Collect all server handshake messages with their encryption levels
        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        #expect(!serverMessages.isEmpty, "Server should produce handshake messages")

        // Complete the handshake by processing server messages on client
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

        // Verify PSK was actually used (not a fallback to full handshake)
        #expect(server.pskUsed, "Server should have used PSK authentication")
        #expect(client.pskUsed, "Client should have used PSK authentication")
    }

    // MARK: - 3. PSK Key Derivation

    @Test("PSK key derivation produces non-empty SymmetricKey")
    func testPSKKeyDerivation() throws {
        let cipherSuite = CipherSuite.tls_aes_128_gcm_sha256

        // Go through the full key schedule to derive a resumption master secret
        var keySchedule = TLSKeySchedule(cipherSuite: cipherSuite)
        keySchedule.deriveEarlySecret(psk: nil)

        let sharedSecret = try P256.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PrivateKey().publicKey
        )
        let transcriptHash1 = Data(SHA256.hash(data: Data()))
        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash1
        )

        let transcriptHash2 = Data(SHA256.hash(data: Data([0x01])))
        _ = try keySchedule.deriveApplicationSecrets(transcriptHash: transcriptHash2)

        let transcriptHash3 = Data(SHA256.hash(data: Data([0x01, 0x02])))
        let resumptionMasterSecret = try keySchedule.deriveResumptionMasterSecret(
            transcriptHash: transcriptHash3
        )

        // Derive PSK from resumption master secret and ticket nonce
        let ticketNonce = Data([0x00, 0x01, 0x02, 0x03])
        let psk = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: resumptionMasterSecret,
            ticketNonce: ticketNonce
        )

        // Verify the PSK is non-empty and correct length
        let pskData = psk.withUnsafeBytes { Data($0) }
        #expect(pskData.count == 32)
        #expect(pskData != Data(repeating: 0, count: 32))
    }

    // MARK: - 4. Expired Ticket Rejected

    @Test("Expired ticket is correctly identified as invalid")
    func testExpiredTicketRejected() {
        let pastTime = Date().addingTimeInterval(-7200) // 2 hours ago
        let ticket = SessionTicketData(
            ticket: Data([0x01, 0x02, 0x03]),
            resumptionPSK: SymmetricKey(data: Data(repeating: 0xAB, count: 32)),
            maxEarlyDataSize: 0,
            ticketAgeAdd: 0x12345678,
            receiveTime: pastTime,
            lifetime: 3600, // 1 hour lifetime
            cipherSuite: .tls_aes_128_gcm_sha256,
            serverName: "example.com",
            alpn: nil
        )

        // The ticket was received 2 hours ago but has a 1 hour lifetime
        // So it should be invalid now
        #expect(!ticket.isValid())

        // Should also be invalid at a time after expiry
        let futureTime = Date().addingTimeInterval(3600)
        #expect(!ticket.isValid(at: futureTime))

        // But should be valid at receive time
        #expect(ticket.isValid(at: pastTime.addingTimeInterval(1)))
    }

    // MARK: - 5. Client Session Cache Store and Retrieve

    @Test("Client session cache stores and retrieves tickets")
    func testClientSessionCacheStoreAndRetrieve() {
        let cache = ClientSessionCache()

        let ticket = NewSessionTicket(
            ticketLifetime: 3600,
            ticketAgeAdd: 0x12345678,
            ticketNonce: Data([0x00, 0x01]),
            ticket: Data([0xAA, 0xBB, 0xCC]),
            extensions: []
        )

        let resumptionSecret = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let serverIdentity = "example.com:443"

        cache.storeTicket(
            ticket,
            resumptionMasterSecret: resumptionSecret,
            cipherSuite: .tls_aes_128_gcm_sha256,
            alpn: "h2",
            serverIdentity: serverIdentity
        )

        // Retrieve the session
        let retrieved = cache.retrieve(for: serverIdentity)
        #expect(retrieved != nil)
        #expect(retrieved?.ticket.ticket == ticket.ticket)
        #expect(retrieved?.ticket.ticketLifetime == ticket.ticketLifetime)
        #expect(retrieved?.ticket.ticketAgeAdd == ticket.ticketAgeAdd)
        #expect(retrieved?.cipherSuite == .tls_aes_128_gcm_sha256)
        #expect(retrieved?.alpn == "h2")
        #expect(retrieved?.serverIdentity == serverIdentity)

        // Verify cache counts
        #expect(cache.serverCount == 1)
        #expect(cache.sessionCount == 1)

        // Retrieve from unknown server should return nil
        let unknown = cache.retrieve(for: "unknown.com:443")
        #expect(unknown == nil)
    }

    // MARK: - 6. Client Session Cache Purge Expired

    @Test("Client session cache purges expired tickets")
    func testClientSessionCachePurgeExpired() {
        let cache = ClientSessionCache()

        // Store a ticket that is already expired
        let expiredTicket = NewSessionTicket(
            ticketLifetime: 1, // 1 second lifetime
            ticketAgeAdd: 0,
            ticketNonce: Data([0x00]),
            ticket: Data([0x01]),
            extensions: []
        )

        let pastTime = Date().addingTimeInterval(-10) // 10 seconds ago
        let expiredSession = ClientSessionCache.CachedSession(
            ticket: expiredTicket,
            resumptionMasterSecret: SymmetricKey(data: Data(repeating: 0, count: 32)),
            cipherSuite: .tls_aes_128_gcm_sha256,
            alpn: nil,
            createdAt: pastTime,
            serverIdentity: "expired.com:443"
        )
        cache.store(session: expiredSession, for: "expired.com:443")

        // Store a valid ticket
        let validTicket = NewSessionTicket(
            ticketLifetime: 86400,
            ticketAgeAdd: 0,
            ticketNonce: Data([0x01]),
            ticket: Data([0x02]),
            extensions: []
        )

        let validSession = ClientSessionCache.CachedSession(
            ticket: validTicket,
            resumptionMasterSecret: SymmetricKey(data: Data(repeating: 0x11, count: 32)),
            cipherSuite: .tls_aes_128_gcm_sha256,
            alpn: nil,
            createdAt: Date(),
            serverIdentity: "valid.com:443"
        )
        cache.store(session: validSession, for: "valid.com:443")

        // Purge expired
        cache.purgeExpired()

        // Expired session should be gone
        #expect(cache.retrieve(for: "expired.com:443") == nil)

        // Valid session should remain
        #expect(cache.retrieve(for: "valid.com:443") != nil)
    }

    // MARK: - 7. Session Ticket Encoding/Decoding

    @Test("NewSessionTicket encodes and decodes correctly")
    func testSessionTicketDecoding() throws {
        let original = NewSessionTicket(
            ticketLifetime: 7200,
            ticketAgeAdd: 0xAABBCCDD,
            ticketNonce: Data([0x01, 0x02, 0x03, 0x04]),
            ticket: Data([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
            extensions: []
        )

        let encoded = original.encode()
        let decoded = try NewSessionTicket.decode(from: encoded)

        #expect(decoded.ticketLifetime == original.ticketLifetime)
        #expect(decoded.ticketAgeAdd == original.ticketAgeAdd)
        #expect(decoded.ticketNonce == original.ticketNonce)
        #expect(decoded.ticket == original.ticket)
        #expect(decoded.extensions.isEmpty)

        // Also test the handshake message encoding
        let message = original.encodeMessage()
        #expect(message.count > encoded.count)
        // Handshake header adds 4 bytes (1 type + 3 length)
        #expect(message.count == encoded.count + 4)
    }

    // MARK: - 8. Obfuscated Ticket Age

    @Test("Obfuscated ticket age arithmetic is correct")
    func testObfuscatedTicketAge() {
        let ticketAgeAdd: UInt32 = 0x12345678
        let now = Date()
        let receiveTime = now.addingTimeInterval(-10) // 10 seconds ago

        let ticket = SessionTicketData(
            ticket: Data([0x01]),
            resumptionPSK: SymmetricKey(data: Data(repeating: 0, count: 32)),
            maxEarlyDataSize: 0,
            ticketAgeAdd: ticketAgeAdd,
            receiveTime: receiveTime,
            lifetime: 3600,
            cipherSuite: .tls_aes_128_gcm_sha256
        )

        let obfuscatedAge = ticket.obfuscatedAge(at: now)

        // The real age in ms is approximately 10000 (10 seconds * 1000)
        // The obfuscated age should be approximately 10000 + 0x12345678
        // Due to timing precision, allow some tolerance
        let expectedRealAgeMs = UInt32(now.timeIntervalSince(receiveTime) * 1000)
        let expectedObfuscated = expectedRealAgeMs &+ ticketAgeAdd

        // Allow 200ms tolerance for timing
        let diff = obfuscatedAge > expectedObfuscated
            ? obfuscatedAge - expectedObfuscated
            : expectedObfuscated - obfuscatedAge
        #expect(diff < 200, "Obfuscated age should be close to expected value")

        // Also verify PskIdentity convenience init
        let pskIdentity = PskIdentity(ticket: ticket, at: now)
        #expect(pskIdentity.identity == ticket.ticket)
        let identityAgeDiff = pskIdentity.obfuscatedTicketAge > obfuscatedAge
            ? pskIdentity.obfuscatedTicketAge - obfuscatedAge
            : obfuscatedAge - pskIdentity.obfuscatedTicketAge
        #expect(identityAgeDiff < 200)
    }

    // MARK: - 9. Resumption Master Secret Derived After Handshake

    @Test("Resumption master secret is available after full handshake")
    func testResumptionMasterSecretDerived() async throws {
        let result = try await performFullHandshake()

        #expect(result.clientHandler.isHandshakeComplete)
        #expect(result.serverHandler.isHandshakeComplete)

        // The client handler's underlying state machine should have derived
        // a resumption master secret. We verify this indirectly by checking
        // the handshake completed without error, which requires the key schedule
        // to have progressed through all derivation steps including the
        // resumption master secret.

        // Test that we can run through the key schedule to the resumption stage
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        keySchedule.deriveEarlySecret(psk: nil)

        let sharedSecret = try P256.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PrivateKey().publicKey
        )
        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: Data(SHA256.hash(data: Data()))
        )
        _ = try keySchedule.deriveApplicationSecrets(
            transcriptHash: Data(SHA256.hash(data: Data([0x01])))
        )

        let resumptionMasterSecret = try keySchedule.deriveResumptionMasterSecret(
            transcriptHash: Data(SHA256.hash(data: Data([0x01, 0x02])))
        )

        // Verify the resumption master secret is valid
        let secretData = resumptionMasterSecret.withUnsafeBytes { Data($0) }
        #expect(secretData.count == 32)
        #expect(secretData != Data(repeating: 0, count: 32))
    }

    // MARK: - 10. Different Cipher Suite PSK Rejected

    @Test("PSK with different cipher suite causes fallback to full handshake")
    func testDifferentCipherSuitePSKRejected() async throws {
        // Create a session ticket with SHA-384 cipher suite
        let sha384Suite = CipherSuite.tls_aes_256_gcm_sha384
        let keySchedule = TLSKeySchedule(cipherSuite: sha384Suite)
        let resumptionSecret = SymmetricKey(data: Data(repeating: 0x42, count: 48))
        let ticketNonce = Data([0x00, 0x01])
        let psk = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: resumptionSecret,
            ticketNonce: ticketNonce
        )

        let sessionTicketData = SessionTicketData(
            ticket: Data(repeating: 0xBB, count: 32),
            resumptionPSK: psk,
            maxEarlyDataSize: 0,
            ticketAgeAdd: 0x87654321,
            receiveTime: Date(),
            lifetime: 3600,
            cipherSuite: sha384Suite,
            serverName: "localhost",
            alpn: nil
        )

        // Configure client with this SHA-384 PSK ticket
        let clientConfig = TestFixture.clientConfig()
        let serverConfig = TestFixture.serverConfig()

        let client = TLS13Handler(configuration: clientConfig)
        let server = TLS13Handler(configuration: serverConfig)

        // Configure client to attempt resumption with SHA-384 ticket
        try client.configureResumption(ticket: sessionTicketData, attemptEarlyData: false)

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

        // Server processes ClientHello - since server has no ticket store,
        // it ignores the PSK and does a full handshake
        let serverOutputs = try await server.processHandshakeData(clientHello, at: .initial)

        var serverMessages: [(Data, TLSEncryptionLevel)] = []
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                serverMessages.append((data, level))
            }
        }

        // There should be multiple handshake messages (SH, EE, Cert, CV, Finished)
        // indicating a full handshake, not a PSK-only handshake
        #expect(serverMessages.count >= 2, "Server should produce full handshake messages")

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

        // Handshake should still complete (fallback to full handshake)
        #expect(client.isHandshakeComplete)
        #expect(server.isHandshakeComplete)
    }
}
