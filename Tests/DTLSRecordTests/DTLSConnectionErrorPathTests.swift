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

    @Test("Tampered ciphertext after handshake is discarded, not fatal")
    func tamperedCiphertextAfterHandshakeIsDiscarded() throws {
        let (client, server) = try performHandshake()

        let plaintext = Data("secret message".utf8)
        var encrypted = try client.writeApplicationData(plaintext)

        // Flip a byte in the ciphertext portion (after the 13-byte header + 8-byte nonce)
        let tamperOffset = 13 + 8 + 2 // somewhere in the ciphertext
        if tamperOffset < encrypted.count {
            encrypted[tamperOffset] ^= 0xFF
        }

        // RFC 6347 §4.1.2.7: a record that fails AEAD authentication is silently
        // discarded at the wire level and must NOT throw or terminate the connection.
        // The anomaly is surfaced so it is observable but non-fatal.
        let output = try server.processReceivedDatagram(encrypted)
        #expect(output.applicationData.isEmpty, "Forged record must not yield plaintext")
        #expect(output.anomalies.contains(.authenticationFailed),
                "Bad-MAC record should surface an authenticationFailed anomaly")
        #expect(!server.isClosed, "Connection must remain open after a forged record")
    }

    @Test("Connection remains usable after processing corrupted data")
    func connectionRemainsUsableAfterCorruptedData() throws {
        let (client, server) = try performHandshake()

        // Send valid data first
        let msg1 = Data("message 1".utf8)
        let enc1 = try client.writeApplicationData(msg1)
        let out1 = try server.processReceivedDatagram(enc1)
        #expect(out1.applicationData == msg1)

        // Send corrupted data — discarded, not fatal (RFC 6347 §4.1.2.7).
        var corrupted = try client.writeApplicationData(Data("will be corrupted".utf8))
        if corrupted.count > 20 {
            corrupted[20] ^= 0xFF
        }
        let corruptedOut = try server.processReceivedDatagram(corrupted)
        #expect(corruptedOut.applicationData.isEmpty)
        #expect(corruptedOut.anomalies.contains(.authenticationFailed))

        // Send valid data again — should still work
        let msg3 = Data("message 3".utf8)
        let enc3 = try client.writeApplicationData(msg3)
        let out3 = try server.processReceivedDatagram(enc3)
        #expect(out3.applicationData == msg3, "Connection should remain usable after error")
    }

    @Test("Bad-MAC record does not abort a later valid record in the same datagram")
    func badMacRecordDoesNotAbortLaterValidRecord() throws {
        let (client, server) = try performHandshake()

        // Build a datagram with TWO records: a forged one followed by a valid one.
        let goodPayload = Data("valid after bad".utf8)
        var badRecord = try client.writeApplicationData(Data("forged".utf8))
        // Corrupt the ciphertext of the first record so it fails AEAD authentication.
        let tamperOffset = 13 + 8 + 2
        if tamperOffset < badRecord.count {
            badRecord[tamperOffset] ^= 0xFF
        }
        let goodRecord = try client.writeApplicationData(goodPayload)

        var datagram = Data()
        datagram.append(badRecord)
        datagram.append(goodRecord)

        let output = try server.processReceivedDatagram(datagram)
        #expect(output.anomalies.contains(.authenticationFailed),
                "The forged record should be reported as discarded")
        #expect(output.applicationData == goodPayload,
                "The valid record following a bad-MAC record must still be processed")
        #expect(!server.isClosed)
    }

    @Test("Short epoch>0 record is discarded without trapping")
    func shortEncryptedRecordIsDiscarded() throws {
        let (client, server) = try performHandshake()

        // Craft a record at the active epoch (1, after a completed handshake) whose
        // fragment is far shorter than the AEAD overhead (8-byte explicit nonce +
        // 16-byte tag = 24 bytes). This previously trapped while building AAD
        // (UInt16 of a negative plaintext length).
        let shortFragment = Data(repeating: 0x00, count: 10) // < 24 bytes
        let record = DTLSRecord(
            contentType: .applicationData,
            epoch: 1,
            sequenceNumber: 42,
            fragment: shortFragment
        )
        let datagram = record.encode()

        // Must not crash; the record is discarded as malformed and no plaintext emitted.
        let output = try server.processReceivedDatagram(datagram)
        #expect(output.applicationData.isEmpty)
        #expect(output.anomalies.contains(.malformed),
                "A sub-overhead encrypted record should be reported as malformed")
        #expect(!server.isClosed)

        // Connection still usable afterwards.
        let msg = Data("ok".utf8)
        let enc = try client.writeApplicationData(msg)
        let out = try server.processReceivedDatagram(enc)
        #expect(out.applicationData == msg)
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
