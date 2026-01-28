/// DTLSConnection Error Path Tests
///
/// Tests the error resilience invariants:
/// A. Corrupted datagrams do not crash or corrupt state
/// B. Operations before handshake are rejected
/// C. Maximum retransmission exhaustion surfaces correctly
/// D. Handshake cannot be restarted

import Testing
import Foundation
import Crypto
@testable import DTLSRecord
@testable import DTLSCore
import TLSCore

@Suite("DTLSConnection Error Path Tests")
struct DTLSConnectionErrorPathTests {

    // MARK: - Contract A: Corrupted Datagrams

    @Test("Truncated record does not crash")
    func truncatedRecordDoesNotCrash() throws {
        let (client, server) = try performHandshake()

        // 5 bytes is less than DTLS header size (13 bytes)
        let truncated = Data([0x17, 0xFE, 0xFD, 0x00, 0x01])

        // Should not crash — record layer returns nil for insufficient data
        let output = try server.processReceivedDatagram(truncated)
        #expect(output.datagramsToSend.isEmpty)
        #expect(output.applicationData.isEmpty)

        // Connection should still work
        let plaintext = Data("still works".utf8)
        let encrypted = try client.writeApplicationData(plaintext)
        let result = try server.processReceivedDatagram(encrypted)
        #expect(result.applicationData == plaintext)
    }

    @Test("Invalid content type throws")
    func invalidContentTypeThrows() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)
        _ = try conn.startHandshake(isClient: true)

        // Construct a datagram with invalid content type (0xFF)
        // Full 13-byte header: contentType(1) + version(2) + epoch(2) + seqNum(6) + length(2)
        var datagram = Data(count: 13 + 1)
        datagram[0] = 0xFF  // invalid content type
        datagram[1] = 0xFE  // DTLS 1.2 major
        datagram[2] = 0xFD  // DTLS 1.2 minor
        // epoch = 0 (bytes 3-4)
        // seqNum = 0 (bytes 5-10)
        datagram[11] = 0x00 // length high
        datagram[12] = 0x01 // length = 1
        datagram[13] = 0x00 // 1 byte payload

        #expect(throws: (any Error).self) {
            _ = try conn.processReceivedDatagram(datagram)
        }
    }

    @Test("Tampered ciphertext after handshake throws")
    func tamperedCiphertextAfterHandshakeThrows() throws {
        let (client, server) = try performHandshake()

        let plaintext = Data("secret message".utf8)
        var encrypted = try client.writeApplicationData(plaintext)

        // Flip a byte in the ciphertext portion (after the 13-byte header + 8-byte nonce)
        let tamperOffset = 13 + 8 + 2 // somewhere in the ciphertext
        if tamperOffset < encrypted.count {
            encrypted[tamperOffset] ^= 0xFF
        }

        #expect(throws: (any Error).self) {
            _ = try server.processReceivedDatagram(encrypted)
        }
    }

    @Test("Connection remains usable after processing corrupted data")
    func connectionRemainsUsableAfterCorruptedData() throws {
        let (client, server) = try performHandshake()

        // Send valid data first
        let msg1 = Data("message 1".utf8)
        let enc1 = try client.writeApplicationData(msg1)
        let out1 = try server.processReceivedDatagram(enc1)
        #expect(out1.applicationData == msg1)

        // Send corrupted data
        var corrupted = try client.writeApplicationData(Data("will be corrupted".utf8))
        if corrupted.count > 20 {
            corrupted[20] ^= 0xFF
        }
        do {
            _ = try server.processReceivedDatagram(corrupted)
            Issue.record("Expected error from corrupted data")
        } catch {
            // Expected — error should not corrupt state
        }

        // Send valid data again — should still work
        let msg3 = Data("message 3".utf8)
        let enc3 = try client.writeApplicationData(msg3)
        let out3 = try server.processReceivedDatagram(enc3)
        #expect(out3.applicationData == msg3, "Connection should remain usable after error")
    }

    // MARK: - Contract B: Pre-Handshake Operations

    @Test("processReceivedDatagram before startHandshake throws")
    func processReceivedBeforeStartHandshakeThrows() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        #expect(throws: DTLSConnectionError.self) {
            _ = try conn.processReceivedDatagram(Data([0x16, 0x00]))
        }
    }

    // MARK: - Contract C: Retransmission Exhaustion

    @Test("handleTimeout throws after max retransmissions")
    func handleTimeoutThrowsAfterMaxRetransmissions() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        // Start handshake to register a flight
        _ = try conn.startHandshake(isClient: true)
        #expect(conn.isAwaitingResponse)

        // 6 retransmissions succeed
        for _ in 0..<6 {
            _ = try conn.handleTimeout()
        }

        // 7th should fail
        #expect(throws: (any Error).self) {
            _ = try conn.handleTimeout()
        }
    }

    @Test("handleTimeout with no active flight throws")
    func handleTimeoutWithNoActiveFlightThrows() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        // Server starts but sends no flight
        _ = try conn.startHandshake(isClient: false)
        #expect(!conn.isAwaitingResponse)

        #expect(throws: (any Error).self) {
            _ = try conn.handleTimeout()
        }
    }

    // MARK: - Contract D: No Handshake Restart

    @Test("startHandshake after completion throws")
    func startHandshakeAfterCompletionThrows() throws {
        let (client, _) = try performHandshake()
        #expect(client.isConnected)

        #expect(throws: DTLSConnectionError.self) {
            _ = try client.startHandshake(isClient: true)
        }
    }

    // MARK: - Helpers

    /// Perform a full handshake and return the connected client and server
    private func performHandshake() throws -> (DTLSConnection, DTLSConnection) {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let client = DTLSConnection(certificate: clientCert)
        let server = DTLSConnection(certificate: serverCert)

        let clientHello = try client.startHandshake(isClient: true)
        _ = try server.startHandshake(isClient: false)

        var clientToServer = clientHello
        var serverToClient: [Data] = []

        for _ in 0..<10 {
            for dg in clientToServer {
                let output = try server.processReceivedDatagram(
                    dg, remoteAddress: Data([192, 168, 1, 1])
                )
                serverToClient.append(contentsOf: output.datagramsToSend)
            }
            clientToServer = []

            if client.isConnected && server.isConnected { break }

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
