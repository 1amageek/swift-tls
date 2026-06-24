/// DTLS 1.2 client-authentication tests
///
/// Verifies the server's mandatory CertificateVerify check (proof of possession)
/// and the `requireClientCertificate` policy. These guard against an attacker
/// presenting a victim's certificate without holding its private key.

import Foundation
import Testing
import DTLSWireCore
import TLSWireCore
import TLSCore
@testable import DTLSCore

@Suite("DTLS Client Authentication")
struct ClientAuthenticationTests {

    // MARK: - Drivers

    /// A client/server pair driven through the cookie exchange + server flight,
    /// then with the client's flight actions captured but NOT yet delivered.
    private struct Pair {
        let client: DTLSClientHandshakeHandler
        let server: DTLSServerHandshakeHandler
        let clientFlight: [DTLSHandshakeAction]
    }

    private func makePair(
        clientCert: DTLSCertificate,
        serverCert: DTLSCertificate,
        requireClientCertificate: Bool
    ) throws -> Pair {
        let client = DTLSClientHandshakeHandler(certificate: clientCert)
        let server = DTLSServerHandshakeHandler(
            certificate: serverCert,
            requireClientCertificate: requireClientCertificate
        )

        let addr = Data([1, 2, 3, 4])

        // ClientHello → HelloVerifyRequest → ClientHello(cookie)
        guard case .sendMessage(let ch1) = try client.startHandshake()[0] else {
            throw DTLSError.handshakeFailed("No ClientHello")
        }
        guard case .sendMessage(let hvr) = try server.processClientHello(ch1, clientAddress: addr)[0] else {
            throw DTLSError.handshakeFailed("No HVR")
        }
        guard case .sendMessage(let ch2) = try client.processHandshakeMessage(hvr)[0] else {
            throw DTLSError.handshakeFailed("No ClientHello2")
        }

        // Server flight
        let serverFlight = try server.processClientHello(ch2, clientAddress: addr)
        var serverMessages: [Data] = []
        for action in serverFlight {
            if case .sendMessage(let msg) = action { serverMessages.append(msg) }
        }

        // Client processes server flight and produces its own flight
        var clientFlight: [DTLSHandshakeAction] = []
        for msg in serverMessages {
            clientFlight.append(contentsOf: try client.processHandshakeMessage(msg))
        }

        return Pair(client: client, server: server, clientFlight: clientFlight)
    }

    /// Feed the client's flight to the server, optionally replacing the
    /// CertificateVerify message. Returns whether the server completed.
    @discardableResult
    private func deliverClientFlight(
        _ flight: [DTLSHandshakeAction],
        to server: DTLSServerHandshakeHandler,
        replacingCertificateVerify forgedCV: Data? = nil,
        omitCertificateAndVerify: Bool = false
    ) throws -> Bool {
        var serverComplete = false

        // Deliver handshake messages up to (and excluding) Finished, then CCS, then Finished.
        var finishedMsg: Data?
        for action in flight {
            switch action {
            case .sendMessage(let msg):
                let firstByte = msg.first
                if firstByte == DTLSHandshakeType.finished.rawValue {
                    finishedMsg = msg
                    continue
                }
                if omitCertificateAndVerify,
                   firstByte == DTLSHandshakeType.certificate.rawValue
                    || firstByte == DTLSHandshakeType.certificateVerify.rawValue {
                    continue
                }
                if firstByte == DTLSHandshakeType.certificateVerify.rawValue, let forged = forgedCV {
                    _ = try server.processHandshakeMessage(forged)
                    continue
                }
                _ = try server.processHandshakeMessage(msg)
            case .sendChangeCipherSpec:
                try server.processChangeCipherSpec()
            default:
                break
            }
        }

        if let fin = finishedMsg {
            let actions = try server.processHandshakeMessage(fin)
            serverComplete = actions.contains { if case .handshakeComplete = $0 { return true } else { return false } }
        }
        return serverComplete
    }

    /// Build a forged CertificateVerify signed by `attackerKey` instead of the
    /// key that matches the presented certificate.
    private func forgedCertificateVerify(signingKey: SigningKey, messageSeq: UInt16) throws -> Data {
        let cv = try CertificateVerify.create(
            handshakeHash: Data(repeating: 0xAB, count: 32),
            signingKey: signingKey
        )
        return DTLSHandshakeHeader.encodeMessage(
            type: .certificateVerify,
            messageSeq: messageSeq,
            body: cv.encode()
        )
    }

    // MARK: - Tests

    @Test("Mutual auth happy path completes when client proves possession")
    func mutualAuthHappyPath() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()
        let pair = try makePair(
            clientCert: clientCert,
            serverCert: serverCert,
            requireClientCertificate: true
        )
        let complete = try deliverClientFlight(pair.clientFlight, to: pair.server)
        #expect(complete)
        #expect(pair.server.isComplete)
        #expect(pair.server.clientCertificateDER != nil)
    }

    @Test("Server rejects a forged CertificateVerify (wrong signing key)")
    func serverRejectsForgedCertificateVerify() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()
        let attackerCert = try DTLSCertificate.generateSelfSigned()

        let pair = try makePair(
            clientCert: clientCert,
            serverCert: serverCert,
            requireClientCertificate: true
        )

        // The attacker presents the (real) client certificate but signs the
        // CertificateVerify with a DIFFERENT key it actually controls.
        // Use the real CertificateVerify message_seq (3: Certificate=1, CKE=2, CV=3)
        // so the message is accepted in order and the signature check is what fails.
        let forged = try forgedCertificateVerify(
            signingKey: attackerCert.signingKey,
            messageSeq: 3
        )

        #expect(throws: DTLSError.self) {
            _ = try deliverClientFlight(
                pair.clientFlight,
                to: pair.server,
                replacingCertificateVerify: forged
            )
        }
        #expect(!pair.server.isComplete)
    }

    @Test("Server with requireClientCertificate rejects a client that omits its certificate")
    func serverRejectsMissingClientCertificate() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()
        let pair = try makePair(
            clientCert: clientCert,
            serverCert: serverCert,
            requireClientCertificate: true
        )

        #expect(throws: DTLSError.self) {
            _ = try deliverClientFlight(
                pair.clientFlight,
                to: pair.server,
                omitCertificateAndVerify: true
            )
        }
        #expect(!pair.server.isComplete)
    }

    @Test("Default server (no requirement) still rejects a presented-but-forged certificate")
    func defaultServerRejectsForgedVerifyWhenCertificatePresented() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()
        let attackerCert = try DTLSCertificate.generateSelfSigned()

        // requireClientCertificate = false, but the client DID present a cert,
        // so it must still prove possession.
        let pair = try makePair(
            clientCert: clientCert,
            serverCert: serverCert,
            requireClientCertificate: false
        )
        let forged = try forgedCertificateVerify(
            signingKey: attackerCert.signingKey,
            messageSeq: 3
        )
        #expect(throws: DTLSError.self) {
            _ = try deliverClientFlight(
                pair.clientFlight,
                to: pair.server,
                replacingCertificateVerify: forged
            )
        }
    }
}
