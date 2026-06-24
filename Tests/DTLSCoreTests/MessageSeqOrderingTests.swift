/// DTLS Handshake message_seq Ordering / Dedup Tests (RFC 6347 §4.2.2)
///
/// Verifies that a duplicated or reordered handshake message does not corrupt the
/// transcript: duplicates (seq < expected) are silently discarded and not re-appended
/// to the transcript, future-seq messages (seq > expected) are rejected, and the
/// handshake still completes when valid messages are duplicated.

import Foundation
import Testing
import DTLSWireCore
import TLSWireCore
import TLSCore
@testable import DTLSCore

@Suite("DTLS Handshake message_seq Ordering")
struct MessageSeqOrderingTests {

    /// Drive a client/server pair through the cookie exchange and capture the
    /// server's flight messages [ServerHello, Certificate, SKE, ServerHelloDone].
    private func driveToServerFlight() throws -> (
        client: DTLSClientHandshakeHandler,
        server: DTLSServerHandshakeHandler,
        serverFlight: [Data]
    ) {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()
        let provider = DTLSCookieSecretProvider()

        let client = DTLSClientHandshakeHandler(certificate: clientCert)
        let server = DTLSServerHandshakeHandler(certificate: serverCert, cookieProvider: provider)
        let addr = Data([1, 2, 3, 4])

        guard case .sendMessage(let ch1) = try client.startHandshake()[0] else {
            throw DTLSError.handshakeFailed("No ClientHello")
        }
        guard case .sendMessage(let hvr) = try server.processClientHello(ch1, clientAddress: addr)[0] else {
            throw DTLSError.handshakeFailed("No HVR")
        }
        guard case .sendMessage(let ch2) = try client.processHandshakeMessage(hvr)[0] else {
            throw DTLSError.handshakeFailed("No ClientHello2")
        }
        let flightActions = try server.processClientHello(ch2, clientAddress: addr)
        var serverFlight: [Data] = []
        for action in flightActions {
            if case .sendMessage(let msg) = action { serverFlight.append(msg) }
        }
        return (client, server, serverFlight)
    }

    @Test("Duplicated ServerHello is discarded and does not corrupt the transcript")
    func duplicatedServerHelloDoesNotCorruptTranscript() throws {
        let (client, _, serverFlight) = try driveToServerFlight()

        // Deliver ServerHello, then a DUPLICATE ServerHello (same seq), then the rest.
        // The duplicate must be silently discarded (no transcript append, no state change).
        let serverHello = serverFlight[0]

        _ = try client.processHandshakeMessage(serverHello)
        #expect(client.currentState == .waitingCertificate)

        // Duplicate ServerHello: returns no actions and leaves state untouched.
        let dupActions = try client.processHandshakeMessage(serverHello)
        #expect(dupActions.isEmpty, "Duplicate ServerHello should produce no actions")
        #expect(client.currentState == .waitingCertificate, "Duplicate must not advance/rewind state")

        // Deliver the remaining flight (Certificate, SKE, ServerHelloDone). If the
        // duplicate had corrupted the transcript, the resulting client flight (which
        // includes a CertificateVerify and Finished bound to the transcript) would be
        // wrong — but here the client should produce its flight successfully.
        var clientFlight: [DTLSHandshakeAction] = []
        for msg in serverFlight[1...] {
            clientFlight.append(contentsOf: try client.processHandshakeMessage(msg))
        }
        #expect(client.currentState == .waitingChangeCipherSpec)
        let sentFinished = clientFlight.contains {
            if case .sendMessage(let m) = $0 { return m.first == DTLSHandshakeType.finished.rawValue }
            return false
        }
        #expect(sentFinished, "Client should emit its flight including Finished")
    }

    @Test("Duplicated Certificate mid-flight does not corrupt the transcript; handshake completes")
    func duplicatedCertificateHandshakeCompletes() throws {
        let (client, server, serverFlight) = try driveToServerFlight()

        // Deliver ServerHello, Certificate, then a DUPLICATE Certificate, then the rest.
        _ = try client.processHandshakeMessage(serverFlight[0]) // ServerHello
        _ = try client.processHandshakeMessage(serverFlight[1]) // Certificate
        #expect(client.currentState == .waitingServerKeyExchange)

        let dupActions = try client.processHandshakeMessage(serverFlight[1]) // duplicate Certificate
        #expect(dupActions.isEmpty)
        #expect(client.currentState == .waitingServerKeyExchange, "Duplicate must not change state")

        var clientFlight: [DTLSHandshakeAction] = []
        for msg in serverFlight[2...] { // SKE, ServerHelloDone
            clientFlight.append(contentsOf: try client.processHandshakeMessage(msg))
        }
        #expect(client.currentState == .waitingChangeCipherSpec)

        // Feed the client's flight to the server. If the transcript were corrupted by
        // the duplicate, the server's verify_data check on the client Finished would
        // fail. Deliver Certificate/CKE/CV, CCS, then Finished.
        var finishedMsg: Data?
        for action in clientFlight {
            switch action {
            case .sendMessage(let msg):
                if msg.first == DTLSHandshakeType.finished.rawValue {
                    finishedMsg = msg
                } else {
                    _ = try server.processHandshakeMessage(msg)
                }
            case .sendChangeCipherSpec:
                try server.processChangeCipherSpec()
            default:
                break
            }
        }
        let fin = try #require(finishedMsg)
        let actions = try server.processHandshakeMessage(fin)
        let completed = actions.contains { if case .handshakeComplete = $0 { return true } else { return false } }
        #expect(completed, "Server must complete; transcript was not corrupted by the duplicate")
        #expect(server.isComplete)
    }

    @Test("Out-of-order (future-seq) handshake message is rejected")
    func futureSeqMessageRejected() throws {
        let (client, _, serverFlight) = try driveToServerFlight()

        _ = try client.processHandshakeMessage(serverFlight[0]) // ServerHello → expects Certificate next
        let expected = client.nextExpectedReceiveSeq

        // Re-stamp the ServerHelloDone with a seq far ahead of expected.
        let shdBody = ServerHelloDone().encode()
        let futureMsg = DTLSHandshakeHeader.encodeMessage(
            type: .serverHelloDone,
            messageSeq: expected &+ 5,
            body: shdBody
        )

        #expect(throws: DTLSError.self) {
            _ = try client.processHandshakeMessage(futureMsg)
        }
    }
}
