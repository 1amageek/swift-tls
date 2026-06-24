/// Facade-level tests for the Tier-1 `DTLSClient` / `DTLSServer` API.
///
/// Exercises the new `[UInt8]` / `Span<UInt8>` DTLS surface end-to-end: the full
/// handshake including the HelloVerifyRequest cookie exchange (RFC 6347 §4.2.1),
/// and application-data round-trip. The engine-level DTLS security tests (cookie
/// binding to a different address, replay, fragmentation, mutual auth) remain
/// unchanged in their own files; this proves the facade drives the same engine.

import Testing
import DTLSWireCore
import TLSWireCore
import Foundation
import Crypto

@testable import TLS
@testable import DTLSCore

@Suite("Facade DTLSClient/DTLSServer Tests")
struct FacadeDTLSClientServerTests {

    private static let remote: [UInt8] = [192, 168, 1, 1]

    private static func identity() throws -> TLSIdentity {
        let cert = try DTLSCertificate.generateSelfSigned(commonName: "facade-dtls")
        return TLSIdentity(
            privateKey: [UInt8](cert.privateKey.rawRepresentation),
            keyType: .ecdsaP256,
            certificateChain: [Certificate(der: [UInt8](cert.derEncoded))]
        )
    }

    private static func makeClientServer() throws -> (DTLSClient, DTLSServer) {
        let client = try DTLSClient(configuration: DTLSConfiguration(identity: try identity(), requireClientCertificate: false))
        let server = try DTLSServer(configuration: DTLSConfiguration(identity: try identity(), requireClientCertificate: false))
        return (client, server)
    }

    /// Drives the full DTLS handshake (with cookie exchange) over the facade.
    private static func performHandshake() throws -> (DTLSClient, DTLSServer) {
        let (client, server) = try makeClientServer()

        let addr = remote
        // 1. Client → ClientHello
        let clientHello = try client.startHandshake()
        _ = try server.startHandshake()
        #expect(clientHello.count == 1)

        // 2. Server → HelloVerifyRequest (cookie)
        let ch1 = clientHello[0]
        let hvr = try server.receive(ch1.span, from: addr.span)
        #expect(!hvr.datagramsToSend.isEmpty)

        // 3. Client → ClientHello with cookie
        let hvrDgram = hvr.datagramsToSend[0]
        let ch2 = try client.receive(hvrDgram.span)
        #expect(!ch2.datagramsToSend.isEmpty)

        // 4. Server → server flight
        let ch2Dgram = ch2.datagramsToSend[0]
        let serverFlight = try server.receive(ch2Dgram.span, from: addr.span)
        #expect(!serverFlight.datagramsToSend.isEmpty)

        // 5. Client → client flight
        let sfDgram = serverFlight.datagramsToSend[0]
        let clientFlight = try client.receive(sfDgram.span)
        #expect(!clientFlight.datagramsToSend.isEmpty)

        // 6. Server → CCS + Finished (server complete)
        let cfDgram = clientFlight.datagramsToSend[0]
        let serverFinish = try server.receive(cfDgram.span, from: addr.span)
        #expect(serverFinish.handshakeComplete)
        #expect(server.isEstablished)

        // 7. Client receives server Finished (client complete)
        let sFinDgram = serverFinish.datagramsToSend[0]
        let clientFinish = try client.receive(sFinDgram.span)
        #expect(clientFinish.handshakeComplete)
        #expect(client.isEstablished)

        return (client, server)
    }

    @Test("Facade DTLS handshake completes via cookie exchange")
    func handshakeCompletes() throws {
        let (client, server) = try Self.performHandshake()
        #expect(client.isEstablished)
        #expect(server.isEstablished)
    }

    @Test("Facade DTLS exchanges application data")
    func exchangesApplicationData() throws {
        let (client, server) = try Self.performHandshake()

        let addr = Self.remote
        let message = [UInt8]("Hello facade DTLS".utf8)
        let datagram = try client.send(message.span)
        let serverGot = try server.receive(datagram.span, from: addr.span)
        #expect(serverGot.applicationData == message)

        let reply = [UInt8]("DTLS reply".utf8)
        let replyDatagram = try server.send(reply.span)
        let clientGot = try client.receive(replyDatagram.span)
        #expect(clientGot.applicationData == reply)
    }

    @Test("Facade DTLS rejects sending before the handshake completes")
    func sendBeforeHandshakeFails() throws {
        let (client, _) = try Self.makeClientServer()
        let early = [UInt8]("early".utf8)
        #expect(throws: TLS.TLSError.self) {
            _ = try client.send(early.span)
        }
    }

    // MARK: - Peer-certificate / fingerprint surfacing (WebRTC DTLS-SRTP unblock)

    @Test("Completed DTLS handshake surfaces the server's certificate to the client")
    func handshakeSurfacesRemoteCertificate() throws {
        let (client, _) = try Self.performHandshake()
        #expect(client.isEstablished)

        // The client received the server's Certificate during the handshake; its
        // DER and SHA-256 fingerprint (RFC 8122 / SDP form) must surface.
        let der = client.remoteCertificateDER
        #expect(der != nil)
        #expect(der?.isEmpty == false)

        let fingerprint = client.remoteFingerprint
        #expect(fingerprint != nil)
        #expect(fingerprint?.hasPrefix("sha-256 ") == true)
    }

    @Test("DTLS peer cert is nil before the handshake completes")
    func remoteCertificateNilBeforeHandshake() throws {
        let (client, _) = try Self.makeClientServer()
        #expect(client.remoteCertificateDER == nil)
        #expect(client.remoteFingerprint == nil)
    }
}
