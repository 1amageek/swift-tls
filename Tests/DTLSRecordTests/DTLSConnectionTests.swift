/// Tests for DTLSConnection end-to-end handshake and application data

import Testing
import Foundation
import Crypto
@testable import DTLSRecord
@testable import DTLSCore
import TLSCore

@Suite("DTLSConnection Tests")
struct DTLSConnectionTests {

    @Test("Initialization creates unconnected state")
    func initialization() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        #expect(!conn.isConnected)
        #expect(conn.remoteCertificateDER == nil)
        #expect(conn.remoteFingerprint == nil)
        #expect(conn.negotiatedCipherSuite == nil)
    }

    @Test("Client startHandshake returns ClientHello datagram")
    func clientStart() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        let datagrams = try conn.startHandshake(isClient: true)

        #expect(datagrams.count == 1)
        #expect(!datagrams[0].isEmpty)
        #expect(!conn.isConnected)
    }

    @Test("Server startHandshake returns empty")
    func serverStart() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        let datagrams = try conn.startHandshake(isClient: false)

        #expect(datagrams.isEmpty)
        #expect(!conn.isConnected)
    }

    @Test("Double startHandshake throws")
    func doubleStart() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        #expect(throws: DTLSConnectionError.self) {
            _ = try conn.startHandshake(isClient: true)
        }
    }

    @Test("writeApplicationData before handshake throws")
    func writeBeforeHandshake() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        #expect(throws: DTLSConnectionError.self) {
            _ = try conn.writeApplicationData(Data("hello".utf8))
        }
    }

    @Test("End-to-end handshake between client and server")
    func endToEndHandshake() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let client = DTLSConnection(certificate: clientCert)
        let server = DTLSConnection(certificate: serverCert)

        // Step 1: Client sends ClientHello
        let clientHelloDgrams = try client.startHandshake(isClient: true)
        _ = try server.startHandshake(isClient: false)
        #expect(clientHelloDgrams.count == 1)

        // Step 2: Server receives ClientHello, sends HelloVerifyRequest
        let hvrOutput = try server.processReceivedDatagram(
            clientHelloDgrams[0],
            remoteAddress: Data([192, 168, 1, 1])
        )
        #expect(!hvrOutput.datagramsToSend.isEmpty)
        #expect(!hvrOutput.handshakeComplete)

        // Step 3: Client receives HVR, sends ClientHello with cookie
        let ch2Output = try client.processReceivedDatagram(hvrOutput.datagramsToSend[0])
        #expect(!ch2Output.datagramsToSend.isEmpty)
        #expect(!ch2Output.handshakeComplete)

        // Step 4: Server receives ClientHello with cookie, sends server flight
        let serverFlightOutput = try server.processReceivedDatagram(
            ch2Output.datagramsToSend[0],
            remoteAddress: Data([192, 168, 1, 1])
        )
        #expect(!serverFlightOutput.datagramsToSend.isEmpty)
        #expect(!serverFlightOutput.handshakeComplete)

        // Step 5: Client receives server flight, sends client flight
        // (Certificate, ClientKeyExchange, CertificateVerify, CCS, encrypted Finished)
        let clientFlightOutput = try client.processReceivedDatagram(
            serverFlightOutput.datagramsToSend[0]
        )
        #expect(!clientFlightOutput.datagramsToSend.isEmpty)
        #expect(!clientFlightOutput.handshakeComplete)
        #expect(!client.isConnected) // Not yet — waiting for server CCS+Finished

        // Step 6: Server receives client flight, sends CCS + encrypted Finished
        let serverFinishOutput = try server.processReceivedDatagram(
            clientFlightOutput.datagramsToSend[0],
            remoteAddress: Data([192, 168, 1, 1])
        )
        #expect(!serverFinishOutput.datagramsToSend.isEmpty)
        #expect(serverFinishOutput.handshakeComplete, "Server handshake should be complete")
        #expect(server.isConnected, "Server should be connected")

        // Step 7: Client receives server CCS + Finished
        let clientFinishOutput = try client.processReceivedDatagram(
            serverFinishOutput.datagramsToSend[0]
        )
        #expect(clientFinishOutput.handshakeComplete, "Client handshake should be complete")
        #expect(client.isConnected, "Client should be connected")

        // Verify negotiated parameters
        #expect(client.negotiatedCipherSuite == .ecdheEcdsaWithAes128GcmSha256)
        #expect(server.negotiatedCipherSuite == .ecdheEcdsaWithAes128GcmSha256)

        // Verify certificates
        #expect(client.remoteCertificateDER == serverCert.derEncoded)
        #expect(server.remoteCertificateDER == clientCert.derEncoded)

        // Verify fingerprints
        #expect(client.remoteFingerprint == serverCert.fingerprint)
    }

    @Test("Application data exchange after handshake")
    func applicationDataExchange() throws {
        let (client, server) = try performHandshake()

        // Client sends application data
        let plaintext = Data("Hello from client".utf8)
        let encrypted = try client.writeApplicationData(plaintext)

        // Server receives and decrypts
        let output = try server.processReceivedDatagram(encrypted)
        #expect(output.applicationData == plaintext)
        #expect(output.datagramsToSend.isEmpty)

        // Server sends application data
        let serverPlaintext = Data("Hello from server".utf8)
        let serverEncrypted = try server.writeApplicationData(serverPlaintext)

        // Client receives and decrypts
        let clientOutput = try client.processReceivedDatagram(serverEncrypted)
        #expect(clientOutput.applicationData == serverPlaintext)
    }

    @Test("Multiple application data exchanges")
    func multipleDataExchanges() throws {
        let (client, server) = try performHandshake()

        for i in 0..<10 {
            let data = Data("Message \(i)".utf8)

            // Client → Server
            let encrypted = try client.writeApplicationData(data)
            let output = try server.processReceivedDatagram(encrypted)
            #expect(output.applicationData == data)

            // Server → Client
            let reply = Data("Reply \(i)".utf8)
            let replyEncrypted = try server.writeApplicationData(reply)
            let replyOutput = try client.processReceivedDatagram(replyEncrypted)
            #expect(replyOutput.applicationData == reply)
        }
    }

    @Test("Certificate fingerprint after handshake")
    func certificateFingerprint() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let (client, server) = try performHandshake(
            clientCert: clientCert,
            serverCert: serverCert
        )

        // Client sees server's fingerprint
        let clientFP = client.remoteFingerprint
        #expect(clientFP != nil)
        #expect(clientFP == serverCert.fingerprint)
        #expect(clientFP?.algorithm == .sha256)

        // Server sees client's fingerprint
        let serverFP = server.remoteFingerprint
        #expect(serverFP != nil)
        #expect(serverFP == clientCert.fingerprint)
    }

    @Test("Retransmission timeout returns flight data")
    func retransmissionTimeout() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        #expect(conn.isAwaitingResponse)

        // Simulate timeout
        let retransmitted = try conn.handleTimeout()
        #expect(!retransmitted.isEmpty)
    }

    // MARK: - Helpers

    /// Perform a full handshake and return the connected client and server
    private func performHandshake(
        clientCert: DTLSCertificate? = nil,
        serverCert: DTLSCertificate? = nil
    ) throws -> (DTLSConnection, DTLSConnection) {
        let cc = try clientCert ?? DTLSCertificate.generateSelfSigned()
        let sc = try serverCert ?? DTLSCertificate.generateSelfSigned()

        let client = DTLSConnection(certificate: cc)
        let server = DTLSConnection(certificate: sc)

        let clientHello = try client.startHandshake(isClient: true)
        _ = try server.startHandshake(isClient: false)

        // Exchange datagrams until both connected
        var clientToServer = clientHello
        var serverToClient: [Data] = []

        for _ in 0..<10 {
            // Client → Server
            for dg in clientToServer {
                let output = try server.processReceivedDatagram(
                    dg,
                    remoteAddress: Data([192, 168, 1, 1])
                )
                serverToClient.append(contentsOf: output.datagramsToSend)
            }
            clientToServer = []

            if client.isConnected && server.isConnected { break }

            // Server → Client
            for dg in serverToClient {
                let output = try client.processReceivedDatagram(dg)
                clientToServer.append(contentsOf: output.datagramsToSend)
            }
            serverToClient = []

            if client.isConnected && server.isConnected { break }
        }

        guard client.isConnected && server.isConnected else {
            throw DTLSConnectionError.fatalProtocolError("Handshake did not complete")
        }

        return (client, server)
    }
}
