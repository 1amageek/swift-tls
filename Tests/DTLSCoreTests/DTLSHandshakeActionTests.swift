/// Tests for DTLS Handshake Action API and transcript hash correctness

import Testing
import Foundation
import Crypto
@testable import DTLSCore
import TLSCore

@Suite("DTLSHandshakeAction Tests")
struct DTLSHandshakeActionTests {

    @Test("Client startHandshake returns sendMessage action")
    func clientStart() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let handler = DTLSClientHandshakeHandler(certificate: cert)

        let actions = handler.startHandshake()
        #expect(actions.count == 1)

        guard case .sendMessage(let msg) = actions[0] else {
            Issue.record("Expected .sendMessage, got \(actions[0])")
            return
        }

        // Verify message is a ClientHello
        #expect(msg.first == DTLSHandshakeType.clientHello.rawValue)
        #expect(handler.currentState == .waitingServerHello)
    }

    @Test("Server processClientHello without cookie returns HelloVerifyRequest")
    func serverHelloVerifyRequest() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let serverHandler = DTLSServerHandshakeHandler(certificate: cert)

        // Build a ClientHello raw message
        let clientHello = DTLSClientHello(cipherSuites: [.ecdheEcdsaWithAes128GcmSha256])
        let chBody = clientHello.encode()
        let chMsg = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: 0,
            body: chBody
        )

        let actions = try serverHandler.processClientHello(chMsg, clientAddress: Data([1, 2, 3, 4]))

        #expect(actions.count == 1)
        guard case .sendMessage(let msg) = actions[0] else {
            Issue.record("Expected .sendMessage, got \(actions[0])")
            return
        }

        // Verify message is a HelloVerifyRequest
        #expect(msg.first == DTLSHandshakeType.helloVerifyRequest.rawValue)
        #expect(serverHandler.currentState == .waitingClientHelloWithCookie)
    }

    @Test("Client flight includes keysAvailable and sendChangeCipherSpec")
    func clientFlightActionSequence() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let clientHandler = DTLSClientHandshakeHandler(certificate: clientCert)
        let serverHandler = DTLSServerHandshakeHandler(certificate: serverCert)

        // Client → ClientHello
        let clientHelloActions = clientHandler.startHandshake()
        guard case .sendMessage(let chMsg) = clientHelloActions[0] else { return }

        // Server → HelloVerifyRequest
        let hvrActions = try serverHandler.processClientHello(chMsg, clientAddress: Data([1, 2, 3, 4]))
        guard case .sendMessage(let hvrMsg) = hvrActions[0] else { return }

        // Client → ClientHello with cookie
        let ch2Actions = try clientHandler.processHandshakeMessage(hvrMsg)
        guard case .sendMessage(let ch2Msg) = ch2Actions[0] else { return }

        // Server → ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
        let serverFlightActions = try serverHandler.processClientHello(ch2Msg, clientAddress: Data([1, 2, 3, 4]))
        #expect(serverFlightActions.count == 4) // All sendMessage

        // Client processes server flight
        var clientResponseActions: [DTLSHandshakeAction] = []
        for action in serverFlightActions {
            if case .sendMessage(let msg) = action {
                let response = try clientHandler.processHandshakeMessage(msg)
                clientResponseActions.append(contentsOf: response)
            }
        }

        // Verify the client flight structure:
        // [sendMessage(cert), sendMessage(cke), sendMessage(cv),
        //  keysAvailable, sendChangeCipherSpec, sendMessage(finished), expectChangeCipherSpec]
        #expect(clientResponseActions.count == 7)

        var hasKeysAvailable = false
        var hasSendCCS = false
        var hasExpectCCS = false
        var sendMessageCount = 0

        for action in clientResponseActions {
            switch action {
            case .sendMessage: sendMessageCount += 1
            case .keysAvailable: hasKeysAvailable = true
            case .sendChangeCipherSpec: hasSendCCS = true
            case .expectChangeCipherSpec: hasExpectCCS = true
            case .handshakeComplete: break
            }
        }

        #expect(sendMessageCount == 4) // cert, cke, cv, finished
        #expect(hasKeysAvailable)
        #expect(hasSendCCS)
        #expect(hasExpectCCS)
        #expect(clientHandler.currentState == .waitingChangeCipherSpec)
    }

    @Test("End-to-end handshake at handler level with transcript hash verification")
    func endToEndHandlerHandshake() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let clientHandler = DTLSClientHandshakeHandler(certificate: clientCert)
        let serverHandler = DTLSServerHandshakeHandler(certificate: serverCert)

        // Client starts handshake
        var clientActions = clientHandler.startHandshake()

        // Exchange messages until both complete
        var iterations = 0
        let maxIterations = 10

        while (!clientHandler.isComplete || !serverHandler.isComplete) && iterations < maxIterations {
            iterations += 1

            // Process client → server
            var newServerActions: [DTLSHandshakeAction] = []
            for action in clientActions {
                switch action {
                case .sendMessage(let msg):
                    if msg.first == DTLSHandshakeType.clientHello.rawValue {
                        let actions = try serverHandler.processClientHello(
                            msg,
                            clientAddress: Data([1, 2, 3, 4])
                        )
                        newServerActions.append(contentsOf: actions)
                    } else {
                        let actions = try serverHandler.processHandshakeMessage(msg)
                        newServerActions.append(contentsOf: actions)
                    }
                case .sendChangeCipherSpec:
                    try serverHandler.processChangeCipherSpec()
                default:
                    break
                }
            }

            // Process server → client
            var newClientActions: [DTLSHandshakeAction] = []
            for action in newServerActions {
                switch action {
                case .sendMessage(let msg):
                    let actions = try clientHandler.processHandshakeMessage(msg)
                    newClientActions.append(contentsOf: actions)
                case .sendChangeCipherSpec:
                    try clientHandler.processChangeCipherSpec()
                default:
                    break
                }
            }

            clientActions = newClientActions
        }

        // Both handlers must be complete
        #expect(clientHandler.isComplete, "Client handshake did not complete")
        #expect(serverHandler.isComplete, "Server handshake did not complete")
        #expect(iterations <= maxIterations, "Handshake did not converge")

        // Verify both handlers have the correct peer certificates
        #expect(clientHandler.serverCertificateDER == serverCert.derEncoded)
        #expect(serverHandler.clientCertificateDER == clientCert.derEncoded)

        // Verify negotiated cipher suite
        #expect(clientHandler.negotiatedCipherSuite == .ecdheEcdsaWithAes128GcmSha256)
        #expect(serverHandler.negotiatedCipherSuite == .ecdheEcdsaWithAes128GcmSha256)
    }

    @Test("Server keysAvailable emitted from ClientKeyExchange processing")
    func serverKeysAvailableFromClientKeyExchange() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        let clientHandler = DTLSClientHandshakeHandler(certificate: clientCert)
        let serverHandler = DTLSServerHandshakeHandler(certificate: serverCert)

        // Run through handshake until client sends its flight
        let ch1 = clientHandler.startHandshake()
        guard case .sendMessage(let chMsg) = ch1[0] else { return }
        let hvr = try serverHandler.processClientHello(chMsg, clientAddress: Data([1, 2, 3, 4]))
        guard case .sendMessage(let hvrMsg) = hvr[0] else { return }
        let ch2 = try clientHandler.processHandshakeMessage(hvrMsg)
        guard case .sendMessage(let ch2Msg) = ch2[0] else { return }
        let serverFlight = try serverHandler.processClientHello(ch2Msg, clientAddress: Data([1, 2, 3, 4]))

        // Feed server messages to client → get client flight
        var clientFlight: [DTLSHandshakeAction] = []
        for action in serverFlight {
            if case .sendMessage(let msg) = action {
                let response = try clientHandler.processHandshakeMessage(msg)
                clientFlight.append(contentsOf: response)
            }
        }

        // Extract handshake messages from client flight and feed to server
        // Process: cert → cke (should emit keysAvailable) → cv
        var serverResponseActions: [DTLSHandshakeAction] = []
        for action in clientFlight {
            switch action {
            case .sendMessage(let msg):
                let msgType = msg.first
                if msgType == DTLSHandshakeType.finished.rawValue {
                    // Skip Finished for now — test keysAvailable from CKE
                    break
                }
                let actions = try serverHandler.processHandshakeMessage(msg)
                serverResponseActions.append(contentsOf: actions)
            default:
                break
            }
        }

        // Server should have emitted keysAvailable after ClientKeyExchange
        let hasKeysAvailable = serverResponseActions.contains(where: {
            if case .keysAvailable = $0 { return true }
            return false
        })
        #expect(hasKeysAvailable, "Server should emit keysAvailable after ClientKeyExchange")

        let hasExpectCCS = serverResponseActions.contains(where: {
            if case .expectChangeCipherSpec = $0 { return true }
            return false
        })
        #expect(hasExpectCCS, "Server should emit expectChangeCipherSpec after ClientKeyExchange")
    }
}
