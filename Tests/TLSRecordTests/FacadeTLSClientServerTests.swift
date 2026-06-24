/// Facade-level tests for the Tier-1 `TLSClient` / `TLSServer` API.
///
/// These exercise the new `[UInt8]` / `Span<UInt8>` surface end-to-end (the clean
/// break from the old `Data`-based `TLSConnection`). They preserve the same
/// behaviours the engine-level integration tests cover — full handshake,
/// bidirectional application-data round-trip, fragmentation, and graceful close —
/// through the public facade. The engine-level security tests (forged
/// CertificateVerify, Finished MAC, downgrade, etc.) remain unchanged in their own
/// files; this file proves the facade faithfully drives the same engine.

import Testing
import TLSWireCore
import Foundation
import Crypto

@testable import TLS
@testable import TLSCore
@testable import DTLSCore

@Suite("Facade TLSClient/TLSServer Tests")
struct FacadeTLSClientServerTests {

    // A real self-signed ECDSA P-256 leaf certificate + key, reused for the
    // server identity. Using a real cert (not a stub) keeps the facade path
    // honest through certificate parsing.
    private static func serverIdentity() throws -> TLSIdentity {
        let cert = try DTLSCertificate.generateSelfSigned(commonName: "facade-test")
        let rawKey = [UInt8](cert.privateKey.rawRepresentation)
        let der = [UInt8](cert.derEncoded)
        return TLSIdentity(
            privateKey: rawKey,
            keyType: .ecdsaP256,
            certificateChain: [Certificate(der: der)]
        )
    }

    private static func makeClientServer() throws -> (TLSClient, TLSServer) {
        let identity = try serverIdentity()
        // Client skips chain trust (verifyPeer = false); the CertificateVerify
        // signature is STILL always verified by the engine — that invariant is
        // not weakened, only X.509 chain trust is skipped for the test.
        let clientConfig = TLSConfiguration(serverName: "facade-test", verifyPeer: false)
        let serverConfig = TLSConfiguration.server(identity: identity)
        let client = try TLSClient(configuration: clientConfig)
        let server = try TLSServer(configuration: serverConfig)
        return (client, server)
    }

    /// Drives a full handshake over the facade surface.
    private static func performHandshake() async throws -> (TLSClient, TLSServer) {
        let (client, server) = try makeClientServer()

        let clientHello = try await client.startHandshake()
        _ = try await server.startHandshake()

        let serverResponse = try await server.receive(clientHello.span)
        let clientResponse = try await client.receive(serverResponse.bytesToSend.span)
        if !clientResponse.bytesToSend.isEmpty {
            _ = try await server.receive(clientResponse.bytesToSend.span)
        }
        return (client, server)
    }

    @Test("Facade handshake completes")
    func handshakeCompletes() async throws {
        let (client, server) = try await Self.performHandshake()
        #expect(client.isEstablished)
        #expect(server.isEstablished)
    }

    @Test("Facade exchanges application data both directions")
    func exchangesApplicationData() async throws {
        let (client, server) = try await Self.performHandshake()

        let message = [UInt8]("Hello facade TLS 1.3".utf8)
        let encrypted = try await client.send(message.span)
        let serverGot = try await server.receive(encrypted.span)
        #expect(serverGot.applicationData == message)

        let reply = [UInt8]("Hello back".utf8)
        let encryptedReply = try await server.send(reply.span)
        let clientGot = try await client.receive(encryptedReply.span)
        #expect(clientGot.applicationData == reply)
    }

    @Test("Facade fragments large application data")
    func fragmentsLargeData() async throws {
        let (client, server) = try await Self.performHandshake()

        // 32KB exceeds the 16KB max TLS plaintext, forcing fragmentation.
        let large = [UInt8](repeating: 0x42, count: 32768)
        let encrypted = try await client.send(large.span)
        #expect(encrypted.count > large.count) // AEAD + record overhead

        let received = try await server.receive(encrypted.span)
        #expect(received.applicationData == large)
    }

    @Test("Facade close emits close_notify the peer observes")
    func closeNotify() async throws {
        let (client, server) = try await Self.performHandshake()

        let closeBytes = try await client.close()
        #expect(!closeBytes.isEmpty)

        let received = try await server.receive(closeBytes.span)
        #expect(received.peerClosed)
    }

    @Test("Facade rejects sending before the handshake completes")
    func sendBeforeHandshakeFails() async throws {
        let (client, _) = try Self.makeClientServer()
        await #expect(throws: TLS.TLSError.self) {
            _ = try await client.send([UInt8]("early".utf8).span)
        }
    }
}
