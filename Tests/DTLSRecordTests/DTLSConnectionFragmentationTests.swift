/// Tests for DTLSConnection handshake fragment reassembly (RFC 6347 §4.2.3)
///
/// These verify that received handshake records are routed through the
/// per-connection `HandshakeReassemblyBuffer`:
/// - a fragmented handshake message (fragment_offset/length < length) is
///   reassembled before being dispatched / recorded in the transcript;
/// - multiple complete handshake messages packed in a single record are all
///   processed in order;
/// - an over-cap fragment is rejected with a typed error;
/// - the non-fragmented happy path is unchanged.

import Testing
import Foundation
import Crypto
@testable import DTLSRecord
@testable import DTLSCore
import TLSCore

@Suite("DTLSConnection Fragmentation Tests")
struct DTLSConnectionFragmentationTests {

    // MARK: - Datagram Rewriting Helpers

    /// Decode every DTLS record from a datagram (records are independent on the
    /// wire; handshake-flight records during the unencrypted phase are epoch 0).
    private func decodeRecords(_ datagram: Data) throws -> [DTLSRecord] {
        var records: [DTLSRecord] = []
        var offset = 0
        while offset < datagram.count {
            let slice = Data(datagram[datagram.startIndex.advanced(by: offset)...])
            guard let (record, consumed) = try DTLSRecord.decode(from: slice) else {
                break
            }
            records.append(record)
            offset += consumed
        }
        return records
    }

    /// Re-encode a list of plaintext records into a single datagram, assigning
    /// fresh ascending sequence numbers within the original epoch. Epoch-0
    /// handshake records carry no replay protection, so sequence numbers are free.
    private func encodeDatagram(_ records: [DTLSRecord]) -> Data {
        var datagram = Data()
        var seq: UInt64 = 0
        for var record in records {
            record.sequenceNumber = seq
            seq += 1
            datagram.append(record.encode())
        }
        return datagram
    }

    /// Rewrite a handshake-flight datagram so that each constituent handshake
    /// message is split into fragments of at most `maxFragmentSize` body bytes,
    /// with each fragment carried in its own DTLS handshake record. Non-handshake
    /// records (if any) are passed through unchanged.
    private func refragment(
        _ datagram: Data,
        maxFragmentSize: Int
    ) throws -> Data {
        let records = try decodeRecords(datagram)
        var rewritten: [DTLSRecord] = []

        for record in records {
            guard record.contentType == .handshake, record.epoch == 0 else {
                rewritten.append(record)
                continue
            }

            // A handshake record may already pack multiple complete messages.
            let messages = try HandshakeReassemblyBuffer.parseMessages(from: record.fragment)
            for message in messages {
                // Each parsed unit here is a complete (non-fragmented) message,
                // so its body is the full message body.
                let fragments = DTLSHandshakeHeader.fragmentMessage(
                    type: message.header.messageType,
                    messageSeq: message.header.messageSeq,
                    body: message.body,
                    maxFragmentSize: maxFragmentSize
                )
                for fragment in fragments {
                    rewritten.append(
                        DTLSRecord(
                            contentType: .handshake,
                            epoch: 0,
                            sequenceNumber: 0,
                            fragment: fragment
                        )
                    )
                }
            }
        }

        return encodeDatagram(rewritten)
    }

    /// Rewrite a handshake-flight datagram so that ALL complete handshake
    /// messages are packed into a SINGLE DTLS handshake record (one record header,
    /// fragment = concatenation of every complete message). This exercises the
    /// "multiple messages in one record" path.
    private func packIntoSingleRecord(_ datagram: Data) throws -> Data {
        let records = try decodeRecords(datagram)
        var packedFragment = Data()
        var passthrough: [DTLSRecord] = []

        for record in records {
            guard record.contentType == .handshake, record.epoch == 0 else {
                passthrough.append(record)
                continue
            }
            // Append the record's payload verbatim. Each handshake-flight record's
            // fragment is one or more complete (non-fragmented) messages, so the
            // concatenation is a valid back-to-back message sequence.
            packedFragment.append(record.fragment)
        }

        var combined: [DTLSRecord] = []
        if !packedFragment.isEmpty {
            combined.append(
                DTLSRecord(
                    contentType: .handshake,
                    epoch: 0,
                    sequenceNumber: 0,
                    fragment: packedFragment
                )
            )
        }
        combined.append(contentsOf: passthrough)
        return encodeDatagram(combined)
    }

    // MARK: - Handshake Driver

    /// Drive the handshake up to (but not processing) the server's first flight
    /// (ServerHello..ServerHelloDone), returning that flight datagram plus the
    /// connected-ready client and server so the caller can finish the handshake.
    private func driveToServerFlight() throws -> (
        client: DTLSConnection,
        server: DTLSConnection,
        serverFlight: Data
    ) {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let client = DTLSConnection(certificate: clientCert)
        let server = DTLSConnection(certificate: serverCert)

        let clientHello = try client.startHandshake(isClient: true)
        _ = try server.startHandshake(isClient: false)

        let hvr = try server.processReceivedDatagram(
            clientHello[0],
            remoteAddress: Data([192, 168, 1, 1])
        )
        let ch2 = try client.processReceivedDatagram(hvr.datagramsToSend[0])
        let serverFlight = try server.processReceivedDatagram(
            ch2.datagramsToSend[0],
            remoteAddress: Data([192, 168, 1, 1])
        )

        return (client, server, serverFlight.datagramsToSend[0])
    }

    /// Finish a handshake given the client's flight, verifying both sides connect.
    private func finishHandshake(
        client: DTLSConnection,
        server: DTLSConnection,
        clientFlight: Data
    ) throws {
        let serverFinish = try server.processReceivedDatagram(
            clientFlight,
            remoteAddress: Data([192, 168, 1, 1])
        )
        #expect(serverFinish.handshakeComplete)
        #expect(server.isConnected)

        let clientFinish = try client.processReceivedDatagram(serverFinish.datagramsToSend[0])
        #expect(clientFinish.handshakeComplete)
        #expect(client.isConnected)
    }

    // MARK: - Tests

    @Test("Fragmented server flight reassembles and handshake completes")
    func testFragmentedServerFlightCompletes() throws {
        let (client, server, serverFlight) = try driveToServerFlight()

        // Split every server-flight handshake message into small fragments, each
        // in its own record. The Certificate/ServerKeyExchange are larger than
        // 32 bytes, so this guarantees genuine fragmentation across records.
        let fragmented = try refragment(serverFlight, maxFragmentSize: 32)

        // Sanity: the rewrite produced more records than the original messages,
        // i.e. real fragmentation occurred.
        let originalRecords = try decodeRecords(serverFlight)
        let fragmentedRecords = try decodeRecords(fragmented)
        #expect(fragmentedRecords.count > originalRecords.count,
                "Re-fragmentation must produce more records than the original flight")

        // The client must reassemble and produce its flight.
        let clientFlight = try client.processReceivedDatagram(fragmented)
        #expect(!clientFlight.datagramsToSend.isEmpty,
                "Client must respond to the reassembled server flight")
        #expect(!clientFlight.handshakeComplete)

        try finishHandshake(client: client, server: server, clientFlight: clientFlight.datagramsToSend[0])
    }

    @Test("Server flight delivered across two datagrams reassembles")
    func testFragmentedAcrossDatagrams() throws {
        let (client, server, serverFlight) = try driveToServerFlight()

        // Build per-record fragments, then deliver them split into two datagrams
        // so reassembly state must persist between processReceivedDatagram calls.
        let fragmented = try refragment(serverFlight, maxFragmentSize: 32)
        let records = try decodeRecords(fragmented)
        #expect(records.count >= 2)

        let mid = records.count / 2
        let firstHalf = encodeDatagram(Array(records[0..<mid]))
        let secondHalf = encodeDatagram(Array(records[mid...]))

        // First datagram: incomplete messages — no client response yet.
        let first = try client.processReceivedDatagram(firstHalf)
        #expect(first.datagramsToSend.isEmpty,
                "Incomplete fragments must not yet trigger a client response")
        #expect(!first.handshakeComplete)

        // Second datagram completes the messages — client responds.
        let second = try client.processReceivedDatagram(secondHalf)
        #expect(!second.datagramsToSend.isEmpty,
                "Completing the fragments must trigger the client flight")

        try finishHandshake(client: client, server: server, clientFlight: second.datagramsToSend[0])
    }

    @Test("Multiple complete messages packed in one record are all processed")
    func testMultipleMessagesInOneRecord() throws {
        let (client, server, serverFlight) = try driveToServerFlight()

        // Pack ServerHello, Certificate, ServerKeyExchange, ServerHelloDone into a
        // single handshake record. Previously only the first would be processed.
        let packed = try packIntoSingleRecord(serverFlight)

        // Sanity: exactly one handshake record now carries all messages.
        let packedRecords = try decodeRecords(packed)
        let handshakeRecords = packedRecords.filter { $0.contentType == .handshake }
        #expect(handshakeRecords.count == 1,
                "All handshake messages must be packed into a single record")
        let messages = try HandshakeReassemblyBuffer.parseMessages(from: handshakeRecords[0].fragment)
        #expect(messages.count >= 4,
                "The single record must contain the full server flight")

        let clientFlight = try client.processReceivedDatagram(packed)
        #expect(!clientFlight.datagramsToSend.isEmpty,
                "Client must process every message in the packed record and respond")

        try finishHandshake(client: client, server: server, clientFlight: clientFlight.datagramsToSend[0])
    }

    @Test("Over-cap handshake fragment is rejected with a typed error")
    func testOverCapFragmentRejected() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let client = DTLSConnection(certificate: cert)
        _ = try client.startHandshake(isClient: true)

        // Craft a fragmented Certificate whose declared total length exceeds the
        // reassembly cap. The fragment body itself is tiny (no eager allocation),
        // but the header's `length` is over the cap, so reassembly must reject it.
        let oversized = HandshakeReassemblyBuffer.maxMessageLength + 1
        var writer = TLSWriter()
        let header = DTLSHandshakeHeader(
            messageType: .certificate,
            length: oversized,
            messageSeq: 1,
            fragmentOffset: 0,
            fragmentLength: 4
        )
        header.encode(writer: &writer)
        writer.writeBytes(Data([0x00, 0x01, 0x02, 0x03]))
        let fragmentMessage = writer.finish()

        let record = DTLSRecord(
            contentType: .handshake,
            epoch: 0,
            sequenceNumber: 0,
            fragment: fragmentMessage
        )
        let datagram = record.encode()

        #expect(throws: DTLSError.self) {
            _ = try client.processReceivedDatagram(datagram)
        }
    }

    @Test("Truncated handshake fragment is rejected with a typed error")
    func testTruncatedFragmentRejected() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let client = DTLSConnection(certificate: cert)
        _ = try client.startHandshake(isClient: true)

        // A handshake record whose body is shorter than the declared fragment
        // length must be rejected (no silent skip of leftover/partial bytes).
        var writer = TLSWriter()
        let header = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 100,
            messageSeq: 1,
            fragmentOffset: 0,
            fragmentLength: 100
        )
        header.encode(writer: &writer)
        writer.writeBytes(Data(repeating: 0x00, count: 10)) // only 10 of 100 bytes
        let truncatedMessage = writer.finish()

        let record = DTLSRecord(
            contentType: .handshake,
            epoch: 0,
            sequenceNumber: 0,
            fragment: truncatedMessage
        )
        let datagram = record.encode()

        #expect(throws: DTLSError.self) {
            _ = try client.processReceivedDatagram(datagram)
        }
    }

    @Test("Non-fragmented handshake path is unchanged")
    func testNonFragmentedPathUnchanged() throws {
        // Control: a normal handshake (no rewriting) must still complete, proving
        // the reassembly wiring does not alter the canonical non-fragmented path.
        let (client, server, serverFlight) = try driveToServerFlight()

        let clientFlight = try client.processReceivedDatagram(serverFlight)
        #expect(!clientFlight.datagramsToSend.isEmpty)
        #expect(!clientFlight.handshakeComplete)

        try finishHandshake(client: client, server: server, clientFlight: clientFlight.datagramsToSend[0])
    }
}
