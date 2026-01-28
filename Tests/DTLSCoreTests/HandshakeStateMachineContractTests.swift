/// Handshake State Machine Contract Tests
///
/// Tests the state machine rejection invariants:
/// A. Messages received in the wrong state are rejected
/// B. Invalid cookies are rejected
/// C. Verify data mismatch is detected
/// D. ChangeCipherSpec in wrong state is rejected

import Testing
import Foundation
import Crypto
@testable import DTLSCore
import TLSCore

@Suite("Handshake State Machine Contract Tests")
struct HandshakeStateMachineContractTests {

    // MARK: - Contract A: Wrong-State Message Rejection

    @Test("Client rejects Certificate in waitingServerHello state")
    func clientRejectsCertificateInWaitingServerHello() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let client = DTLSClientHandshakeHandler(certificate: cert)

        _ = client.startHandshake()
        #expect(client.currentState == .waitingServerHello)

        // Construct a Certificate message
        let certMsg = CertificateMessage(certificates: [Data([0x30, 0x82])])
        let raw = DTLSHandshakeHeader.encodeMessage(
            type: .certificate,
            messageSeq: 0,
            body: certMsg.encode()
        )

        #expect(throws: DTLSError.self) {
            _ = try client.processHandshakeMessage(raw)
        }
    }

    @Test("Client rejects ServerHelloDone before Certificate")
    func clientRejectsServerHelloDoneBeforeCertificate() throws {
        let (client, _, serverFlightMessages) = try setupHandshakePair()

        // Feed only ServerHello → client moves to waitingCertificate
        _ = try client.processHandshakeMessage(serverFlightMessages[0])
        #expect(client.currentState == .waitingCertificate)

        // Construct a ServerHelloDone message (skipping Certificate and SKE)
        let shdBody = ServerHelloDone().encode()
        let shdMsg = DTLSHandshakeHeader.encodeMessage(
            type: .serverHelloDone,
            messageSeq: 0,
            body: shdBody
        )

        #expect(throws: DTLSError.self) {
            _ = try client.processHandshakeMessage(shdMsg)
        }
    }

    @Test("Client rejects Finished before ChangeCipherSpec")
    func clientRejectsFinishedBeforeChangeCipherSpec() throws {
        let (client, _, serverFlightMessages) = try setupHandshakePair()

        // Feed all server messages → client sends its flight, enters waitingChangeCipherSpec
        for msg in serverFlightMessages {
            _ = try client.processHandshakeMessage(msg)
        }
        #expect(client.currentState == .waitingChangeCipherSpec)

        // Construct a Finished message (should only come after CCS)
        let finBody = Data(repeating: 0xAA, count: 12)
        let finMsg = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: 0,
            body: finBody
        )

        #expect(throws: DTLSError.self) {
            _ = try client.processHandshakeMessage(finMsg)
        }
    }

    @Test("Server rejects Finished before ChangeCipherSpec")
    func serverRejectsFinishedBeforeChangeCipherSpec() throws {
        let (client, server, serverFlightMessages) = try setupHandshakePair()

        // Feed server messages to client → get client flight
        var clientFlightActions: [DTLSHandshakeAction] = []
        for msg in serverFlightMessages {
            let actions = try client.processHandshakeMessage(msg)
            clientFlightActions.append(contentsOf: actions)
        }

        // Feed client's Certificate and CKE to server (skip CV and Finished)
        for action in clientFlightActions {
            if case .sendMessage(let msg) = action {
                let firstByte = msg.first
                // Feed Certificate and ClientKeyExchange only
                if firstByte == DTLSHandshakeType.certificate.rawValue ||
                   firstByte == DTLSHandshakeType.clientKeyExchange.rawValue ||
                   firstByte == DTLSHandshakeType.certificateVerify.rawValue {
                    _ = try server.processHandshakeMessage(msg)
                }
            }
        }
        #expect(server.currentState == .waitingChangeCipherSpec)

        // Construct a Finished message (should not be accepted before CCS)
        let finBody = Data(repeating: 0xBB, count: 12)
        let finMsg = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: 0,
            body: finBody
        )

        #expect(throws: DTLSError.self) {
            _ = try server.processHandshakeMessage(finMsg)
        }
    }

    // MARK: - Contract B: Invalid Cookie Rejection

    @Test("Server rejects ClientHello with invalid cookie")
    func serverRejectsInvalidCookie() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let server = DTLSServerHandshakeHandler(certificate: cert)

        // Send initial ClientHello (no cookie) → server stores cookieSecret
        let clientHello = DTLSClientHello(cipherSuites: [.ecdheEcdsaWithAes128GcmSha256])
        let chBody = clientHello.encode()
        let chMsg = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: 0,
            body: chBody
        )
        _ = try server.processClientHello(chMsg, clientAddress: Data([1, 2, 3, 4]))
        #expect(server.currentState == .waitingClientHelloWithCookie)

        // Send ClientHello with garbage cookie
        let badClientHello = DTLSClientHello(
            cookie: Data(repeating: 0xFF, count: 32),
            cipherSuites: [.ecdheEcdsaWithAes128GcmSha256]
        )
        let badBody = badClientHello.encode()
        let badMsg = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: 0,
            body: badBody
        )

        #expect(throws: DTLSError.self) {
            _ = try server.processClientHello(badMsg, clientAddress: Data([1, 2, 3, 4]))
        }
    }

    @Test("Server rejects valid cookie from different address")
    func serverRejectsCookieFromDifferentAddress() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let client = DTLSClientHandshakeHandler(certificate: clientCert)
        let server = DTLSServerHandshakeHandler(certificate: serverCert)

        let addressA = Data([192, 168, 1, 1])
        let addressB = Data([10, 0, 0, 1])

        // Client sends ClientHello
        let ch1Actions = client.startHandshake()
        guard case .sendMessage(let chMsg) = ch1Actions[0] else {
            Issue.record("No ClientHello")
            return
        }

        // Server generates HVR for address A
        let hvrActions = try server.processClientHello(chMsg, clientAddress: addressA)
        guard case .sendMessage(let hvrMsg) = hvrActions[0] else {
            Issue.record("No HVR")
            return
        }

        // Client gets cookie and resends ClientHello
        let ch2Actions = try client.processHandshakeMessage(hvrMsg)
        guard case .sendMessage(let ch2Msg) = ch2Actions[0] else {
            Issue.record("No ClientHello2")
            return
        }

        // Server receives ClientHello with cookie, but from address B
        #expect(throws: DTLSError.self) {
            _ = try server.processClientHello(ch2Msg, clientAddress: addressB)
        }
    }

    // MARK: - Contract C: Verify Data Mismatch

    @Test("Client rejects server Finished with wrong verify data")
    func clientRejectsServerFinishedWithWrongVerifyData() throws {
        let (client, server, serverFlightMessages) = try setupHandshakePair()

        // Feed all server messages to client → client sends flight
        var clientFlightActions: [DTLSHandshakeAction] = []
        for msg in serverFlightMessages {
            let actions = try client.processHandshakeMessage(msg)
            clientFlightActions.append(contentsOf: actions)
        }
        #expect(client.currentState == .waitingChangeCipherSpec)

        // Feed client's messages to server
        for action in clientFlightActions {
            switch action {
            case .sendMessage(let msg):
                if msg.first == DTLSHandshakeType.finished.rawValue {
                    // Skip client Finished for now; process CCS first
                    continue
                }
                _ = try server.processHandshakeMessage(msg)
            case .sendChangeCipherSpec:
                try server.processChangeCipherSpec()
            default:
                break
            }
        }

        // Now feed client Finished to server
        for action in clientFlightActions {
            if case .sendMessage(let msg) = action,
               msg.first == DTLSHandshakeType.finished.rawValue {
                _ = try server.processHandshakeMessage(msg)
                break
            }
        }
        #expect(server.isComplete)

        // Simulate server CCS for client
        try client.processChangeCipherSpec()
        #expect(client.currentState == .waitingFinished)

        // Send Finished with wrong verify_data
        let badFinished = Data(repeating: 0x00, count: 12)
        let badFinMsg = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: 0,
            body: badFinished
        )

        #expect(throws: DTLSError.self) {
            _ = try client.processHandshakeMessage(badFinMsg)
        }
    }

    @Test("Server rejects client Finished with wrong verify data")
    func serverRejectsClientFinishedWithWrongVerifyData() throws {
        let (client, server, serverFlightMessages) = try setupHandshakePair()

        // Feed server messages to client
        var clientFlightActions: [DTLSHandshakeAction] = []
        for msg in serverFlightMessages {
            let actions = try client.processHandshakeMessage(msg)
            clientFlightActions.append(contentsOf: actions)
        }

        // Feed client's Certificate, CKE, CV to server
        for action in clientFlightActions {
            if case .sendMessage(let msg) = action {
                let firstByte = msg.first
                if firstByte == DTLSHandshakeType.certificate.rawValue ||
                   firstByte == DTLSHandshakeType.clientKeyExchange.rawValue ||
                   firstByte == DTLSHandshakeType.certificateVerify.rawValue {
                    _ = try server.processHandshakeMessage(msg)
                }
            }
        }

        // Process CCS on server
        try server.processChangeCipherSpec()
        #expect(server.currentState == .waitingFinished)

        // Send Finished with wrong verify_data
        let badFinished = Data(repeating: 0xFF, count: 12)
        let badFinMsg = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: 0,
            body: badFinished
        )

        #expect(throws: DTLSError.self) {
            _ = try server.processHandshakeMessage(badFinMsg)
        }
    }

    // MARK: - Contract D: CCS in Wrong State

    @Test("Client rejects ChangeCipherSpec in waitingServerHello state")
    func clientRejectsCCSInWrongState() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let client = DTLSClientHandshakeHandler(certificate: cert)

        _ = client.startHandshake()
        #expect(client.currentState == .waitingServerHello)

        #expect(throws: DTLSError.self) {
            try client.processChangeCipherSpec()
        }
    }

    @Test("Server rejects ChangeCipherSpec in waitingClientKeyExchange state")
    func serverRejectsCCSInWrongState() throws {
        let (_, server, _) = try setupHandshakePair()
        #expect(server.currentState == .waitingClientKeyExchange)

        #expect(throws: DTLSError.self) {
            try server.processChangeCipherSpec()
        }
    }

    // MARK: - Helpers

    /// Set up a client-server pair through the cookie exchange and server flight.
    ///
    /// Returns:
    /// - `client`: in `waitingCertificate` state (ServerHello not yet processed)
    ///   or later depending on what the caller feeds
    /// - `server`: in `waitingClientKeyExchange` state
    /// - `serverFlightMessages`: [ServerHello, Certificate, SKE, ServerHelloDone]
    private func setupHandshakePair() throws -> (
        client: DTLSClientHandshakeHandler,
        server: DTLSServerHandshakeHandler,
        serverFlightMessages: [Data]
    ) {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let client = DTLSClientHandshakeHandler(certificate: clientCert)
        let server = DTLSServerHandshakeHandler(certificate: serverCert)

        // Step 1: ClientHello
        let ch1Actions = client.startHandshake()
        guard case .sendMessage(let chMsg) = ch1Actions[0] else {
            throw DTLSError.handshakeFailed("No ClientHello")
        }

        // Step 2: HelloVerifyRequest
        let hvrActions = try server.processClientHello(
            chMsg, clientAddress: Data([1, 2, 3, 4])
        )
        guard case .sendMessage(let hvrMsg) = hvrActions[0] else {
            throw DTLSError.handshakeFailed("No HVR")
        }

        // Step 3: ClientHello with cookie
        let ch2Actions = try client.processHandshakeMessage(hvrMsg)
        guard case .sendMessage(let ch2Msg) = ch2Actions[0] else {
            throw DTLSError.handshakeFailed("No ClientHello2")
        }

        // Step 4: Server flight (ServerHello, Certificate, SKE, ServerHelloDone)
        let serverFlightActions = try server.processClientHello(
            ch2Msg, clientAddress: Data([1, 2, 3, 4])
        )

        var serverMessages: [Data] = []
        for action in serverFlightActions {
            if case .sendMessage(let msg) = action {
                serverMessages.append(msg)
            }
        }

        return (client, server, serverMessages)
    }
}
