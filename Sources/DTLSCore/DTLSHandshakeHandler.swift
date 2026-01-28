/// DTLS 1.2 Handshake Handler
///
/// Integrates state machine, message encoding/decoding, key exchange, and
/// key schedule into a unified handshake processor.
///
/// DTLS 1.2 Full Handshake Flow:
///   Flight 1: Client → ClientHello
///   Flight 2: Server → HelloVerifyRequest
///   Flight 3: Client → ClientHello (with cookie)
///   Flight 4: Server → ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
///   Flight 5: Client → Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished
///   Flight 6: Server → CCS, Finished

import Foundation
import Crypto
import TLSCore

/// Result of processing handshake data
public struct DTLSHandshakeResult: Sendable {
    /// Messages to send to the peer
    public let outputMessages: [Data]

    /// Whether the handshake is complete
    public let isComplete: Bool

    /// Derived key block (available when handshake completes)
    public let keyBlock: DTLSKeyBlock?

    /// The negotiated cipher suite
    public let cipherSuite: DTLSCipherSuite?

    public init(
        outputMessages: [Data] = [],
        isComplete: Bool = false,
        keyBlock: DTLSKeyBlock? = nil,
        cipherSuite: DTLSCipherSuite? = nil
    ) {
        self.outputMessages = outputMessages
        self.isComplete = isComplete
        self.keyBlock = keyBlock
        self.cipherSuite = cipherSuite
    }
}

/// DTLS 1.2 handshake handler for the client side
public struct DTLSClientHandshakeHandler: Sendable {
    private var state: DTLSClientState = .idle
    private var context: DTLSClientContext = DTLSClientContext()
    private let certificate: DTLSCertificate
    private let supportedCipherSuites: [DTLSCipherSuite]

    public init(
        certificate: DTLSCertificate,
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256]
    ) {
        self.certificate = certificate
        self.supportedCipherSuites = supportedCipherSuites
    }

    /// Start the handshake by generating the initial ClientHello
    public mutating func startHandshake() -> DTLSHandshakeResult {
        let clientHello = DTLSClientHello(
            cipherSuites: supportedCipherSuites
        )
        context.clientRandom = clientHello.random

        let body = clientHello.encode()
        let msg = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: context.nextMessageSeq(),
            body: body
        )
        context.handshakeMessages.append(msg)

        state = .waitingServerHello
        return DTLSHandshakeResult(outputMessages: [msg])
    }

    /// Process incoming handshake data
    public mutating func processMessage(type: DTLSHandshakeType, body: Data) throws -> DTLSHandshakeResult {
        switch (state, type) {
        case (.waitingServerHello, .helloVerifyRequest):
            return try handleHelloVerifyRequest(body)

        case (.waitingServerHello, .serverHello),
             (.waitingServerHelloWithCookie, .serverHello):
            try handleServerHello(body)
            state = .waitingCertificate
            return DTLSHandshakeResult()

        case (.waitingCertificate, .certificate):
            try handleCertificate(body)
            state = .waitingServerKeyExchange
            return DTLSHandshakeResult()

        case (.waitingServerKeyExchange, .serverKeyExchange):
            try handleServerKeyExchange(body)
            state = .waitingServerHelloDone
            return DTLSHandshakeResult()

        case (.waitingServerHelloDone, .serverHelloDone):
            return try handleServerHelloDone(body)

        case (.waitingFinished, .finished):
            return try handleServerFinished(body)

        default:
            throw DTLSError.unexpectedMessage(expected: expectedType, received: type)
        }
    }

    /// Process a ChangeCipherSpec (not a handshake message)
    public mutating func processChangeCipherSpec() throws {
        guard state == .waitingChangeCipherSpec else {
            throw DTLSError.invalidState("Unexpected ChangeCipherSpec in state: \(state)")
        }
        state = .waitingFinished
    }

    /// Whether the handshake is complete
    public var isComplete: Bool {
        state == .connected
    }

    /// The current state
    public var currentState: DTLSClientState {
        state
    }

    // MARK: - Private handlers

    private var expectedType: DTLSHandshakeType {
        switch state {
        case .waitingServerHello, .waitingServerHelloWithCookie: return .serverHello
        case .waitingCertificate: return .certificate
        case .waitingServerKeyExchange: return .serverKeyExchange
        case .waitingServerHelloDone: return .serverHelloDone
        case .waitingFinished: return .finished
        default: return .serverHello
        }
    }

    private mutating func handleHelloVerifyRequest(_ body: Data) throws -> DTLSHandshakeResult {
        let hvr = try HelloVerifyRequest.decode(from: body)
        context.cookie = hvr.cookie

        // Reset message seq and handshake hash for the retry
        context.messageSeq = 0
        context.handshakeMessages = Data()

        // Resend ClientHello with cookie
        let clientHello = DTLSClientHello(
            random: context.clientRandom,
            cookie: hvr.cookie,
            cipherSuites: supportedCipherSuites
        )

        let body = clientHello.encode()
        let msg = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: context.nextMessageSeq(),
            body: body
        )
        context.handshakeMessages.append(msg)

        state = .waitingServerHelloWithCookie
        return DTLSHandshakeResult(outputMessages: [msg])
    }

    private mutating func handleServerHello(_ body: Data) throws {
        let serverHello = try DTLSServerHello.decode(from: body)
        context.serverRandom = serverHello.random
        context.cipherSuite = serverHello.cipherSuite
        context.keySchedule = DTLSKeySchedule(cipherSuite: serverHello.cipherSuite)
    }

    private mutating func handleCertificate(_ body: Data) throws {
        let certMsg = try CertificateMessage.decode(from: body)
        guard let firstCert = certMsg.certificates.first else {
            throw DTLSError.invalidCertificate("Empty certificate chain")
        }
        context.serverCertificateDER = firstCert
    }

    private mutating func handleServerKeyExchange(_ body: Data) throws {
        let ske = try ServerKeyExchange.decode(from: body)
        context.serverPublicKey = ske.publicKey
        context.serverNamedGroup = ske.namedGroup

        // Verify server signature using server's certificate
        if let certDER = context.serverCertificateDER {
            let verifyKey = try VerificationKey(certificateData: certDER)

            guard let clientRandom = context.clientRandom,
                  let serverRandom = context.serverRandom else {
                throw DTLSError.invalidState("Missing randoms")
            }

            let valid = try ske.verify(
                clientRandom: clientRandom,
                serverRandom: serverRandom,
                verificationKey: verifyKey
            )
            guard valid else {
                throw DTLSError.signatureVerificationFailed
            }
        }
    }

    private mutating func handleServerHelloDone(_ body: Data) throws -> DTLSHandshakeResult {
        _ = try ServerHelloDone.decode(from: body)

        guard let serverPublicKey = context.serverPublicKey,
              let serverNamedGroup = context.serverNamedGroup,
              let clientRandom = context.clientRandom,
              let serverRandom = context.serverRandom else {
            throw DTLSError.invalidState("Missing handshake data")
        }

        // Generate ECDHE key pair
        let keyExchange = try KeyExchange.generate(for: serverNamedGroup)
        context.keyExchange = keyExchange

        // Compute pre-master secret
        let sharedSecret = try keyExchange.sharedSecret(with: serverPublicKey)

        // Derive master secret and key block
        context.keySchedule?.deriveMasterSecret(
            preMasterSecret: sharedSecret.rawRepresentation,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        var messages: [Data] = []

        // Certificate message
        let certMsg = CertificateMessage(certificate: certificate)
        let certBody = certMsg.encode()
        let certEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .certificate,
            messageSeq: context.nextMessageSeq(),
            body: certBody
        )
        context.handshakeMessages.append(certEncoded)
        messages.append(certEncoded)

        // ClientKeyExchange
        let cke = ClientKeyExchange(publicKey: keyExchange.publicKeyBytes)
        let ckeBody = cke.encode()
        let ckeEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .clientKeyExchange,
            messageSeq: context.nextMessageSeq(),
            body: ckeBody
        )
        context.handshakeMessages.append(ckeEncoded)
        messages.append(ckeEncoded)

        // CertificateVerify
        let handshakeHash = computeHandshakeHash()
        let cv = try CertificateVerify.create(
            handshakeHash: handshakeHash,
            signingKey: certificate.signingKey
        )
        let cvBody = cv.encode()
        let cvEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .certificateVerify,
            messageSeq: context.nextMessageSeq(),
            body: cvBody
        )
        context.handshakeMessages.append(cvEncoded)
        messages.append(cvEncoded)

        // ChangeCipherSpec (not a handshake message, not included in hash)
        let ccs = ChangeCipherSpec()
        messages.append(ccs.encode())

        // Finished
        let finishedHash = computeHandshakeHash()
        let verifyData = try context.keySchedule?.computeVerifyData(
            label: DTLSFinished.clientLabel,
            handshakeHash: finishedHash
        )
        guard let verifyData else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        let finished = DTLSFinished(verifyData: verifyData)
        let finBody = finished.encode()
        let finEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: context.nextMessageSeq(),
            body: finBody
        )
        context.handshakeMessages.append(finEncoded)
        messages.append(finEncoded)

        state = .waitingChangeCipherSpec

        return DTLSHandshakeResult(
            outputMessages: messages,
            cipherSuite: context.cipherSuite
        )
    }

    private mutating func handleServerFinished(_ body: Data) throws -> DTLSHandshakeResult {
        let finished = try DTLSFinished.decode(from: body)

        // Verify server's Finished
        let handshakeHash = computeHandshakeHash()
        let expectedVerifyData = try context.keySchedule?.computeVerifyData(
            label: DTLSFinished.serverLabel,
            handshakeHash: handshakeHash
        )
        guard let expectedVerifyData else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        guard finished.verifyData == expectedVerifyData else {
            throw DTLSError.verifyDataMismatch
        }

        state = .connected

        let keyBlock = try context.keySchedule?.deriveKeyBlock()
        return DTLSHandshakeResult(
            isComplete: true,
            keyBlock: keyBlock,
            cipherSuite: context.cipherSuite
        )
    }

    private func computeHandshakeHash() -> Data {
        Data(SHA256.hash(data: context.handshakeMessages))
    }
}

/// DTLS 1.2 handshake handler for the server side
public struct DTLSServerHandshakeHandler: Sendable {
    private var state: DTLSServerState = .idle
    private var context: DTLSServerContext = DTLSServerContext()
    private let certificate: DTLSCertificate
    private let supportedCipherSuites: [DTLSCipherSuite]

    public init(
        certificate: DTLSCertificate,
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256]
    ) {
        self.certificate = certificate
        self.supportedCipherSuites = supportedCipherSuites
    }

    /// Process initial ClientHello (may return HelloVerifyRequest)
    public mutating func processClientHello(
        _ clientHello: DTLSClientHello,
        clientAddress: Data
    ) throws -> DTLSHandshakeResult {
        // If no cookie, send HelloVerifyRequest
        if clientHello.cookie.isEmpty {
            let secret = generateCookieSecret()
            context.cookieSecret = secret

            let hvr = HelloVerifyRequest.generate(
                clientAddress: clientAddress,
                secret: SymmetricKey(data: secret)
            )
            let body = hvr.encode()
            let msg = DTLSHandshakeHeader.encodeMessage(
                type: .helloVerifyRequest,
                messageSeq: context.nextMessageSeq(),
                body: body
            )

            state = .waitingClientHelloWithCookie
            return DTLSHandshakeResult(outputMessages: [msg])
        }

        // Verify cookie
        if let cookieSecret = context.cookieSecret {
            let valid = HelloVerifyRequest.verifyCookie(
                clientHello.cookie,
                clientAddress: clientAddress,
                secret: SymmetricKey(data: cookieSecret)
            )
            guard valid else {
                throw DTLSError.cookieMismatch
            }
        }

        return try processVerifiedClientHello(clientHello)
    }

    /// Process a verified ClientHello and generate server flight
    private mutating func processVerifiedClientHello(
        _ clientHello: DTLSClientHello
    ) throws -> DTLSHandshakeResult {
        context.clientRandom = clientHello.random

        // Select cipher suite
        guard let selectedSuite = selectCipherSuite(from: clientHello.cipherSuites) else {
            throw DTLSError.noCipherSuiteMatch
        }
        context.cipherSuite = selectedSuite
        context.keySchedule = DTLSKeySchedule(cipherSuite: selectedSuite)

        // Reset handshake messages
        context.handshakeMessages = Data()

        // Add ClientHello to transcript
        let chBody = clientHello.encode()
        let chEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: 0,
            body: chBody
        )
        context.handshakeMessages.append(chEncoded)

        var messages: [Data] = []

        // ServerHello
        let serverHello = DTLSServerHello(cipherSuite: selectedSuite)
        context.serverRandom = serverHello.random
        let shBody = serverHello.encode()
        let shEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .serverHello,
            messageSeq: context.nextMessageSeq(),
            body: shBody
        )
        context.handshakeMessages.append(shEncoded)
        messages.append(shEncoded)

        // Certificate
        let certMsg = CertificateMessage(certificate: certificate)
        let certBody = certMsg.encode()
        let certEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .certificate,
            messageSeq: context.nextMessageSeq(),
            body: certBody
        )
        context.handshakeMessages.append(certEncoded)
        messages.append(certEncoded)

        // ServerKeyExchange
        let namedGroup: TLSCore.NamedGroup = .secp256r1
        let keyExchange = try KeyExchange.generate(for: namedGroup)
        context.keyExchange = keyExchange

        guard let clientRandom = context.clientRandom,
              let serverRandom = context.serverRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }

        let ske = try ServerKeyExchange.create(
            keyExchange: keyExchange,
            signingKey: certificate.signingKey,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )
        let skeBody = ske.encode()
        let skeEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .serverKeyExchange,
            messageSeq: context.nextMessageSeq(),
            body: skeBody
        )
        context.handshakeMessages.append(skeEncoded)
        messages.append(skeEncoded)

        // ServerHelloDone
        let shd = ServerHelloDone()
        let shdBody = shd.encode()
        let shdEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .serverHelloDone,
            messageSeq: context.nextMessageSeq(),
            body: shdBody
        )
        context.handshakeMessages.append(shdEncoded)
        messages.append(shdEncoded)

        state = .waitingClientKeyExchange
        return DTLSHandshakeResult(outputMessages: messages)
    }

    /// Process incoming handshake message
    public mutating func processMessage(type: DTLSHandshakeType, body: Data) throws -> DTLSHandshakeResult {
        switch (state, type) {
        case (.waitingClientHelloWithCookie, .clientHello):
            let clientHello = try DTLSClientHello.decode(from: body)
            return try processVerifiedClientHello(clientHello)

        case (.waitingClientKeyExchange, .certificate):
            let certMsg = try CertificateMessage.decode(from: body)
            context.clientCertificateDER = certMsg.certificates.first
            // Record in transcript
            let encoded = DTLSHandshakeHeader.encodeMessage(
                type: .certificate, messageSeq: 0, body: body
            )
            context.handshakeMessages.append(encoded)
            return DTLSHandshakeResult()

        case (.waitingClientKeyExchange, .clientKeyExchange):
            return try handleClientKeyExchange(body)

        case (.waitingClientKeyExchange, .certificateVerify):
            // Record in transcript
            let encoded = DTLSHandshakeHeader.encodeMessage(
                type: .certificateVerify, messageSeq: 0, body: body
            )
            context.handshakeMessages.append(encoded)
            return DTLSHandshakeResult()

        case (.waitingFinished, .finished):
            return try handleClientFinished(body)

        default:
            throw DTLSError.unexpectedMessage(
                expected: .clientKeyExchange,
                received: type
            )
        }
    }

    /// Process a ChangeCipherSpec
    public mutating func processChangeCipherSpec() throws {
        guard state == .waitingChangeCipherSpec || state == .waitingClientKeyExchange else {
            throw DTLSError.invalidState("Unexpected ChangeCipherSpec in state: \(state)")
        }
        state = .waitingFinished
    }

    /// Whether the handshake is complete
    public var isComplete: Bool {
        state == .connected
    }

    /// The current state
    public var currentState: DTLSServerState {
        state
    }

    // MARK: - Private handlers

    private mutating func handleClientKeyExchange(_ body: Data) throws -> DTLSHandshakeResult {
        let cke = try ClientKeyExchange.decode(from: body)
        context.clientPublicKey = cke.publicKey

        // Record in transcript
        let encoded = DTLSHandshakeHeader.encodeMessage(
            type: .clientKeyExchange, messageSeq: 0, body: body
        )
        context.handshakeMessages.append(encoded)

        // Compute pre-master secret
        guard let keyExchange = context.keyExchange else {
            throw DTLSError.invalidState("No key exchange")
        }
        let sharedSecret = try keyExchange.sharedSecret(with: cke.publicKey)

        guard let clientRandom = context.clientRandom,
              let serverRandom = context.serverRandom else {
            throw DTLSError.invalidState("Missing randoms")
        }

        // Derive master secret
        context.keySchedule?.deriveMasterSecret(
            preMasterSecret: sharedSecret.rawRepresentation,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        state = .waitingChangeCipherSpec
        return DTLSHandshakeResult()
    }

    private mutating func handleClientFinished(_ body: Data) throws -> DTLSHandshakeResult {
        let finished = try DTLSFinished.decode(from: body)

        // Verify client's Finished
        let handshakeHash = computeHandshakeHash()
        let expectedVerifyData = try context.keySchedule?.computeVerifyData(
            label: DTLSFinished.clientLabel,
            handshakeHash: handshakeHash
        )
        guard let expectedVerifyData else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        guard finished.verifyData == expectedVerifyData else {
            throw DTLSError.verifyDataMismatch
        }

        // Add client Finished to transcript
        let finEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .finished, messageSeq: 0, body: body
        )
        context.handshakeMessages.append(finEncoded)

        var messages: [Data] = []

        // Server CCS
        let ccs = ChangeCipherSpec()
        messages.append(ccs.encode())

        // Server Finished
        let serverHash = computeHandshakeHash()
        let verifyData = try context.keySchedule?.computeVerifyData(
            label: DTLSFinished.serverLabel,
            handshakeHash: serverHash
        )
        guard let verifyData else {
            throw DTLSError.invalidState("Key schedule not initialized")
        }

        let serverFinished = DTLSFinished(verifyData: verifyData)
        let sfBody = serverFinished.encode()
        let sfEncoded = DTLSHandshakeHeader.encodeMessage(
            type: .finished,
            messageSeq: context.nextMessageSeq(),
            body: sfBody
        )
        messages.append(sfEncoded)

        state = .connected

        let keyBlock = try context.keySchedule?.deriveKeyBlock()
        return DTLSHandshakeResult(
            outputMessages: messages,
            isComplete: true,
            keyBlock: keyBlock,
            cipherSuite: context.cipherSuite
        )
    }

    private func selectCipherSuite(from offered: [DTLSCipherSuite]) -> DTLSCipherSuite? {
        for suite in supportedCipherSuites {
            if offered.contains(suite) {
                return suite
            }
        }
        return nil
    }

    private func generateCookieSecret() -> Data {
        var bytes = Data(count: 32)
        bytes.withUnsafeMutableBytes { ptr in
            let _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        return bytes
    }

    private func computeHandshakeHash() -> Data {
        Data(SHA256.hash(data: context.handshakeMessages))
    }
}

