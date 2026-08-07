import Testing
import TLS
import TLSCryptoProvider
import DTLSRecordCore
import DTLSWireCore
import SSLCrypto
import Synchronization

@Test
func pureSwiftProviderSignsAndVerifies() throws {
    let signing = try TLSCryptoProvider.P256Signature.generateSigningKey()
    let verifying = TLSCryptoProvider.P256Signature.verifyingKey(for: signing)
    let message = Array("canonical swift-ssl".utf8)
    let signature = try TLSCryptoProvider.P256Signature.sign(message.span, with: signing)

    let valid = signature.withUnsafeBufferPointer { signatureBuffer in
        message.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P256Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(valid)

    var modified = message
    modified[0] ^= 1
    let modifiedValid = signature.withUnsafeBufferPointer { signatureBuffer in
        modified.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P256Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(!modifiedValid)
}

@Test
func pureSwiftProviderP384SignsAndVerifies() throws {
    let signing = try TLSCryptoProvider.P384Signature.generateSigningKey()
    let verifying = TLSCryptoProvider.P384Signature.verifyingKey(for: signing)
    let message = Array("canonical swift-ssl P-384".utf8)
    let signature = try TLSCryptoProvider.P384Signature.sign(message.span, with: signing)
    let valid = signature.withUnsafeBufferPointer { signatureBuffer in
        message.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P384Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(valid)

    var modified = message
    modified[0] ^= 1
    let modifiedValid = signature.withUnsafeBufferPointer { signatureBuffer in
        modified.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P384Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(!modifiedValid)
}

@Test
func pureSwiftProviderRoundTripsAEAD() throws {
    let key = [UInt8](repeating: 0x42, count: 16)
    let nonce = [UInt8](repeating: 0x24, count: 12)
    let aad = Array("header".utf8)
    let plaintext = Array("payload".utf8)
    let aead = try TLSCryptoProvider.makeAESGCM128(key: key.span)
    let ciphertext = try aead.seal(plaintext.span, nonce: nonce.span, aad: aad.span)
    let opened = try aead.open(ciphertext.span, nonce: nonce.span, aad: aad.span)
    #expect(opened == plaintext)
}

@Test
func pureSwiftProviderRoundTripsDTLSRecordProtection() throws {
    let key = [UInt8](repeating: 0x42, count: 16)
    let fixedIV = [UInt8](repeating: 0x24, count: 4)
    let context = try TLSCryptoProvider.makeDTLSAES128RecordProtectionContext(
        key: key,
        fixedIV: fixedIV
    )
    let plaintext = Array("dtls record through SSLDTLS".utf8)
    let explicitNonce: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 1]
    let aad = [UInt8](repeating: 0xA5, count: 13)

    let ciphertext = try context.seal(
        plaintext: plaintext.span,
        explicitNonce: explicitNonce,
        aad: aad
    )
    var callerOwnedCiphertext = [UInt8](
        repeating: 0,
        count: try context.sealedByteCount(forPlaintextByteCount: plaintext.count)
    )
    try callerOwnedCiphertext.withUnsafeMutableBufferPointer { buffer in
        var output = MutableSpan(_unsafeElements: buffer)
        try context.seal(
            plaintext: plaintext.span,
            explicitNonce: explicitNonce,
            aad: aad,
            into: &output
        )
    }
    #expect(callerOwnedCiphertext == ciphertext)
    let opened = try context.open(ciphertext: ciphertext.span, aad: aad)
    #expect(opened == plaintext)

    var tampered = ciphertext
    tampered[tampered.index(before: tampered.endIndex)] ^= 1
    #expect(throws: DTLSRecordProtectionError.self) {
        _ = try context.open(ciphertext: tampered.span, aad: aad)
    }
}

@Test
func dtlsFacadeTransfersApplicationDataInBothDirections() throws {
    let identity = validP256Identity()
    let configuration = DTLSConfiguration(identity: identity)
    let client = try DTLSClient(configuration: configuration)
    let server = try DTLSServer(configuration: configuration)
    let remoteAddress = ContiguousArray<UInt8>([127, 0, 0, 1, 0x1F, 0x90])
    try completeDTLSHandshake(
        client: client,
        server: server,
        remoteAddress: remoteAddress
    )

    let clientPayload = ContiguousArray("client DTLS payload".utf8)
    let clientDatagram = try client.send(clientPayload.span)
    #expect(clientDatagram.count == clientPayload.count + 37)
    let serverOutput = try server.receive(
        clientDatagram.span,
        from: remoteAddress.span
    )
    #expect(serverOutput.applicationData == Array(clientPayload))
    #expect(serverOutput.datagramsToSend.isEmpty)
    #expect(serverOutput.anomalies.isEmpty)

    let serverPayload = ContiguousArray("server DTLS payload".utf8)
    let serverDatagram = try server.send(serverPayload.span)
    #expect(serverDatagram.count == serverPayload.count + 37)
    let clientOutput = try client.receive(serverDatagram.span)
    #expect(clientOutput.applicationData == Array(serverPayload))
    #expect(clientOutput.datagramsToSend.isEmpty)
    #expect(clientOutput.anomalies.isEmpty)
}

@Test
func dtlsCookieRetryKeepsHandshakeMessageSequenceMonotonic() throws {
    let identity = validP256Identity()
    let client = try DTLSClient(configuration: DTLSConfiguration(identity: identity))
    let server = try DTLSServer(configuration: DTLSConfiguration(identity: identity))
    let remoteAddress = ContiguousArray<UInt8>([127, 0, 0, 1, 0x1F, 0x90])

    #expect(try server.startHandshake().isEmpty)
    let initialClientHello = try #require(client.startHandshake().first)
    let initialMessage = try decodeDTLSHandshakeDatagram(initialClientHello)
    #expect(initialMessage.header.messageType == .clientHello)
    #expect(initialMessage.header.messageSeq == 0)

    let helloVerifyOutput = try server.receive(
        ContiguousArray(initialClientHello).span,
        from: remoteAddress.span
    )
    let helloVerifyDatagram = try #require(helloVerifyOutput.datagramsToSend.first)
    let helloVerifyMessage = try decodeDTLSHandshakeDatagram(helloVerifyDatagram)
    #expect(helloVerifyMessage.header.messageType == .helloVerifyRequest)
    #expect(helloVerifyMessage.header.messageSeq == 0)
    let helloVerifyCookie = try decodeHelloVerifyRequestCookie(helloVerifyMessage.body)

    let retryOutput = try client.receive(ContiguousArray(helloVerifyDatagram).span)
    let retryDatagram = try #require(retryOutput.datagramsToSend.first)
    let retryMessage = try decodeDTLSHandshakeDatagram(retryDatagram)
    #expect(retryMessage.header.messageType == .clientHello)
    #expect(retryMessage.header.messageSeq == 1)
    #expect(try DTLSClientHello.decode(from: retryMessage.body).cookie == helloVerifyCookie)

    let serverFlight = try server.receive(
        ContiguousArray(retryDatagram).span,
        from: remoteAddress.span
    )
    let firstServerFlightDatagram = try #require(serverFlight.datagramsToSend.first)
    let firstServerFlightMessage = try decodeDTLSHandshakeDatagram(firstServerFlightDatagram)
    #expect(firstServerFlightMessage.header.messageType == .serverHello)
    #expect(firstServerFlightMessage.header.messageSeq == 1)

    var clientToServer: [[UInt8]] = []
    var serverToClient = serverFlight.datagramsToSend
    var iterations = 0
    while !client.isEstablished || !server.isEstablished {
        iterations += 1
        guard iterations < 64 else {
            throw TLSError.protocolFailure(reason: "DTLS handshake exceeded the test flight limit")
        }
        if !serverToClient.isEmpty {
            let datagram = serverToClient.removeFirst()
            let output = try client.receive(ContiguousArray(datagram).span)
            clientToServer.append(contentsOf: output.datagramsToSend)
        } else if !clientToServer.isEmpty {
            let datagram = clientToServer.removeFirst()
            let output = try server.receive(
                ContiguousArray(datagram).span,
                from: remoteAddress.span
            )
            serverToClient.append(contentsOf: output.datagramsToSend)
        } else {
            throw TLSError.protocolFailure(reason: "DTLS handshake stalled before establishment")
        }
    }
}

@Test
func rawPublicKeyTrustRootsAreValidatedAtTheFacadeBoundary() throws {
    let rawPublicKey = deterministicEd25519SubjectPublicKeyInfo()
    let configuration = TLSConfiguration(
        verifyPeer: true,
        trustRoots: TLSTrustRoots(
            rawPublicKeys: [Certificate(der: rawPublicKey)]
        ),
        certificateTypes: .rawPublicKey
    )
    _ = try TLSClient(configuration: configuration)
}

@Test
func streamRejectsApplicationDataBeforeHandshake() throws {
    let client = try TLSClient(configuration: TLSConfiguration(
        verifyPeer: false,
        certificateTypes: TLSCertificateTypes(
            local: [.x509],
            peer: [.rawPublicKey]
        )
    ))
    do {
        _ = try client.send(ContiguousArray<UInt8>().span)
        Issue.record("send unexpectedly succeeded before handshake")
    } catch let error {
        #expect(error == .handshakeNotComplete)
    }
}

@Test
func malformedRawPublicKeyTrustRootFailsClosed() {
    let configuration = TLSConfiguration(
        verifyPeer: true,
        trustRoots: TLSTrustRoots(
            rawPublicKeys: [Certificate(der: [0x30, 0x00])]
        ),
        certificateTypes: .rawPublicKey
    )
    #expect(throws: TLSError.self) {
        _ = try TLSClient(configuration: configuration)
    }
}

@Test
func rawIdentityPrivateKeyMismatchFailsBeforeHandshake() {
    let identity = TLSIdentity(
        privateKey: [UInt8](repeating: 0, count: 32),
        keyType: .ed25519,
        certificateChain: [],
        rawPublicKey: Certificate(der: deterministicEd25519SubjectPublicKeyInfo())
    )
    let configuration = TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey,
        requireClientCertificate: true
    )
    #expect(throws: TLSError.self) {
        _ = try TLSServer(configuration: configuration)
    }
}

@Test
func rawServerIdentityCanAuthenticateAnX509Peer() throws {
    let identity = validRawIdentity()
    let configuration = TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: TLSCertificateTypes(
            local: [.rawPublicKey],
            peer: [.x509]
        )
    )
    _ = try TLSServer(configuration: configuration)
}

@Test
func validRawServerIdentityInitializes() throws {
    _ = try TLSServer(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: validRawIdentity(),
        certificateTypes: .rawPublicKey
    ))
}

@Test
func deterministicEd25519FixtureMatchesTheProvider() throws {
    let seed = validRawIdentity().privateKey
    #expect(seed == [
        0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60,
        0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C, 0xC4,
        0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19,
        0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE, 0x7F, 0x60,
    ])
    let ownedSeed = ContiguousArray(seed)
    let directKey = try Ed25519PrivateKey(seed: ownedSeed.span)
    let derived = try directKey.publicKey()
    #expect(Array(derived) == Array(deterministicEd25519SubjectPublicKeyInfo().dropFirst(12)))
    let signingKey = try TLSCryptoProvider.Ed25519.signingKey(rawRepresentation: seed.span)
    let publicKey = TLSCryptoProvider.Ed25519.rawRepresentation(
        of: TLSCryptoProvider.Ed25519.verifyingKey(for: signingKey)
    )
    #expect(publicKey == Array(deterministicEd25519SubjectPublicKeyInfo().dropFirst(12)))
}

@Test
func x509PeerAuthenticationCannotBeEnabledWithoutTrustPolicy() {
    let configuration = TLSConfiguration(
        verifyPeer: true,
        identity: validRawIdentity(),
        certificateTypes: TLSCertificateTypes(
            local: [.rawPublicKey],
            peer: [.x509]
        ),
        requireClientCertificate: true
    )
    #expect(throws: TLSError.self) {
        _ = try TLSServer(configuration: configuration)
    }
}

@Test
func streamFacadeCompletesRawKeyHandshakeAndTransfersApplicationData() throws {
    let identity = validRawIdentity()
    let server = try TLSServer(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey,
        requireClientCertificate: true
    ))
    let client = try TLSClient(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey
    ))

    try completeRawHandshake(client: client, server: server)
    #expect(client.isEstablished)
    #expect(server.isEstablished)

    let plaintext = ContiguousArray("swift-tls application data".utf8)
    let encrypted = try client.send(plaintext.span)
    let received = try server.receive(ContiguousArray(encrypted).span)
    #expect(received.applicationData == Array(plaintext))
}

@Test
func streamPeerCloseNotifyIsTerminalAndPostCloseDataIsRejected() throws {
    let identity = validRawIdentity()
    let server = try TLSServer(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey,
        requireClientCertificate: true
    ))
    let client = try TLSClient(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey
    ))

    try completeRawHandshake(client: client, server: server)
    let encryptedBeforeClose = try client.send(
        ContiguousArray<UInt8>([0xA5]).span
    )
    let closeBytes = try server.close()
    let closeRecords = try splitTLSRecords(ContiguousArray(closeBytes))
    #expect(closeRecords.count == 1)

    var closeOutput = TLSOutput()
    for record in closeRecords {
        closeOutput = try client.receive(record.span)
    }
    #expect(closeOutput.peerClosed)
    #expect(!client.isEstablished)

    do {
        _ = try client.receive(ContiguousArray(encryptedBeforeClose).span)
        Issue.record("receive unexpectedly succeeded after peer close_notify")
    } catch let error {
        #expect(error == .connectionClosed)
    }
    do {
        _ = try client.send(ContiguousArray<UInt8>().span)
        Issue.record("send unexpectedly succeeded after peer close_notify")
    } catch let error {
        #expect(error == .connectionClosed)
    }
}

@Test
func streamKeyUpdateRotatesBothApplicationTrafficDirections() throws {
    let identity = validRawIdentity()
    let server = try TLSServer(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey,
        requireClientCertificate: true
    ))
    let client = try TLSClient(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey
    ))
    try completeRawHandshake(client: client, server: server)

    let update = try server.requestKeyUpdate(requestPeerUpdate: true)
    var responseRecords: [ContiguousArray<UInt8>] = []
    for record in try splitTLSRecords(ContiguousArray(update)) {
        let output = try client.receive(record.span)
        responseRecords.append(contentsOf: try splitTLSRecords(
            ContiguousArray(output.bytesToSend)
        ))
    }
    #expect(!responseRecords.isEmpty)
    for record in responseRecords {
        let output = try server.receive(record.span)
        #expect(output.applicationData.isEmpty)
    }

    let clientPayload = ContiguousArray("client after key update".utf8)
    let serverReceived = try server.receive(
        ContiguousArray(try client.send(clientPayload.span)).span
    )
    #expect(serverReceived.applicationData == Array(clientPayload))

    let serverPayload = ContiguousArray("server after key update".utf8)
    let clientReceived = try client.receive(
        ContiguousArray(try server.send(serverPayload.span)).span
    )
    #expect(clientReceived.applicationData == Array(serverPayload))
}

@Test
func streamNewSessionTicketResumesWithClientAndServerState() throws {
    let identity = validRawIdentity()
    let serverConfiguration = TLSConfiguration(
        verifyPeer: false,
        identity: identity,
        certificateTypes: .rawPublicKey
    )
    let clientConfiguration = TLSConfiguration(
        verifyPeer: false,
        certificateTypes: TLSCertificateTypes(
            local: [.x509],
            peer: [.rawPublicKey]
        )
    )
    let firstServer = try TLSServer(configuration: serverConfiguration)
    let firstClient = try TLSClient(configuration: clientConfiguration)
    try completeRawHandshake(client: firstClient, server: firstServer)

    let issued = try firstServer.sendNewSessionTicket(
        lifetime: 60,
        ageAdd: 7,
        ticketNonce: ContiguousArray([0x01, 0x02]).span,
        ticket: ContiguousArray([0xA0, 0xA1, 0xA2]).span
    )
    let ticketOutput = try firstClient.receive(
        ContiguousArray(issued.bytesToSend).span
    )
    #expect(ticketOutput.sessionTicketReceived)
    let clientState = firstClient.takeResumptionState()
    #expect(clientState != nil)
    #expect(firstClient.takeResumptionState() == nil)

    let resumedServer = try TLSServer(
        configuration: serverConfiguration,
        resumptionState: issued.resumptionState
    )
    #expect(throws: TLSError.self) {
        _ = try TLSServer(
            configuration: serverConfiguration,
            resumptionState: issued.resumptionState
        )
    }
    let resumedClient = try TLSClient(
        configuration: clientConfiguration,
        resumptionState: clientState
    )
    try completeRawHandshake(client: resumedClient, server: resumedServer)
    #expect(resumedClient.isEstablished)
    #expect(resumedServer.isEstablished)
}

@Test
func streamExternalX509PolicyCallbackAuthenticatesPeer() throws {
    let callbackInvocations = Mutex(0)
    let client = try TLSClient(configuration: TLSConfiguration(
        verifyPeer: false,
        certificateTypes: .x509,
        certificateValidator: { certificates in
            callbackInvocations.withLock { $0 += 1 }
            return PeerIdentity(identifier: [0xA5], certificates: certificates)
        }
    ))
    let server = try TLSServer(configuration: TLSConfiguration(
        verifyPeer: false,
        identity: validP256Identity()
    ))

    try completeAutomaticHandshake(client: client, server: server)
    #expect(callbackInvocations.withLock { $0 == 1 })
    #expect(client.peerIdentity?.identifier == [0xA5])
}

private func completeRawHandshake(
    client: TLSClient,
    server: TLSServer
) throws(TLSError) {
    var clientToServer = try splitTLSRecords(ContiguousArray(try client.startHandshake()))
    var serverToClient: [ContiguousArray<UInt8>] = []
    var iterations = 0
    while (!client.isEstablished || !server.isEstablished) &&
        (!clientToServer.isEmpty || !serverToClient.isEmpty) {
        iterations += 1
        guard iterations < 64 else {
            throw .protocolFailure(reason: "TLS handshake exceeded the test flight limit")
        }
        if !clientToServer.isEmpty {
            let record = clientToServer.removeFirst()
            let output: TLSOutput
            do {
                output = try server.receiveStep(record.span)
            } catch let error {
                throw .protocolFailure(reason: "server receive failed: \(error)")
            }
            guard output.capabilityRequest == nil else {
                throw .protocolFailure(reason: "unexpected capability request in raw-key fixture")
            }
            serverToClient.append(contentsOf: try splitTLSRecords(ContiguousArray(output.bytesToSend)))
        } else if !serverToClient.isEmpty {
            let record = serverToClient.removeFirst()
            let output: TLSOutput
            do {
                output = try client.receiveStep(record.span)
            } catch let error {
                throw .protocolFailure(reason: "client receive failed: \(error)")
            }
            guard output.capabilityRequest == nil else {
                throw .protocolFailure(reason: "unexpected capability request in raw-key fixture")
            }
            clientToServer.append(contentsOf: try splitTLSRecords(ContiguousArray(output.bytesToSend)))
        }
    }
    guard client.isEstablished, server.isEstablished else {
        throw .protocolFailure(reason: "TLS handshake stalled before establishment")
    }
}

private func completeAutomaticHandshake(
    client: TLSClient,
    server: TLSServer
) throws(TLSError) {
    var clientToServer = try splitTLSRecords(ContiguousArray(try client.startHandshake()))
    var serverToClient: [ContiguousArray<UInt8>] = []
    var iterations = 0
    while (!client.isEstablished || !server.isEstablished) &&
        (!clientToServer.isEmpty || !serverToClient.isEmpty) {
        iterations += 1
        guard iterations < 64 else {
            throw .protocolFailure(reason: "TLS handshake exceeded the test flight limit")
        }
        if !clientToServer.isEmpty {
            let record = clientToServer.removeFirst()
            let output = try server.receive(record.span)
            serverToClient.append(contentsOf: try splitTLSRecords(ContiguousArray(output.bytesToSend)))
        } else if !serverToClient.isEmpty {
            let record = serverToClient.removeFirst()
            let output = try client.receive(record.span)
            clientToServer.append(contentsOf: try splitTLSRecords(ContiguousArray(output.bytesToSend)))
        }
    }
    guard client.isEstablished, server.isEstablished else {
        throw .protocolFailure(reason: "TLS handshake stalled before establishment")
    }
}

private func completeDTLSHandshake(
    client: DTLSClient,
    server: DTLSServer,
    remoteAddress: ContiguousArray<UInt8>
) throws(TLSError) {
    _ = try server.startHandshake()
    var clientToServer = try client.startHandshake()
    var serverToClient: [[UInt8]] = []
    var iterations = 0
    while !client.isEstablished || !server.isEstablished {
        iterations += 1
        guard iterations < 64 else {
            throw .protocolFailure(reason: "DTLS handshake exceeded the test flight limit")
        }
        if !clientToServer.isEmpty {
            let datagram = clientToServer.removeFirst()
            let output = try server.receive(datagram.span, from: remoteAddress.span)
            serverToClient.append(contentsOf: output.datagramsToSend)
        } else if !serverToClient.isEmpty {
            let datagram = serverToClient.removeFirst()
            let output = try client.receive(datagram.span)
            clientToServer.append(contentsOf: output.datagramsToSend)
        } else {
            throw .protocolFailure(reason: "DTLS handshake stalled before establishment")
        }
    }
}

private func splitTLSRecords(
    _ bytes: ContiguousArray<UInt8>
) throws(TLSError) -> [ContiguousArray<UInt8>] {
    var result: [ContiguousArray<UInt8>] = []
    var offset = 0
    while offset < bytes.count {
        guard bytes.count - offset >= 5 else {
            throw .protocolFailure(reason: "test fixture emitted a truncated TLS record")
        }
        let length = (Int(bytes[offset + 3]) << 8) | Int(bytes[offset + 4])
        let recordCount = 5 + length
        guard recordCount <= bytes.count - offset else {
            throw .protocolFailure(reason: "test fixture emitted an incomplete TLS record")
        }
        var record = ContiguousArray<UInt8>()
        record.reserveCapacity(recordCount)
        for index in offset..<(offset + recordCount) {
            record.append(bytes[index])
        }
        result.append(record)
        offset += recordCount
    }
    return result
}

private func validRawIdentity() -> TLSIdentity {
    TLSIdentity(
        privateKey: [
            0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60,
            0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C, 0xC4,
            0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19,
            0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE, 0x7F, 0x60,
        ],
        keyType: .ed25519,
        certificateChain: [],
        rawPublicKey: Certificate(der: deterministicEd25519SubjectPublicKeyInfo())
    )
}

private func validP256Identity() -> TLSIdentity {
    TLSIdentity(
        privateKey: [UInt8](repeating: 0, count: 31) + [0x01],
        keyType: .ecdsaP256,
        certificateChain: [Certificate(der: p256Certificate())]
    )
}

private func p256Certificate() -> [UInt8] {
    let encoded = "3082016930820110a003020102020107300a06082a8648ce3d04030230223120301e"
        + "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d"
        + "3235303130313030303030305a170d3335303130313030303030305a30223120301e"
        + "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013"
        + "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e"
        + "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f"
        + "9e162bce33576b315ececbb6406837bf51f5a3373035300f0603551d130101ff0405"
        + "30030101ff30220603551d11041b3019821773776966742d73736c2d65636473612e"
        + "6578616d706c65300a06082a8648ce3d040302034700304402207d64b4f0d8d41a49"
        + "720e591dc1844556462cd8beb44558fa9f63156a76f2c6cc022063756eb89655ab0b"
        + "0b04032d184382dd99e0be5ce5cacc66374a36dc83f7ac23"
    var result: [UInt8] = []
    result.reserveCapacity(encoded.count / 2)
    var index = encoded.startIndex
    while index < encoded.endIndex {
        let next = encoded.index(index, offsetBy: 2)
        result.append(UInt8(encoded[index..<next], radix: 16)!)
        index = next
    }
    return result
}

private func decodeDTLSHandshakeDatagram(
    _ datagram: [UInt8]
) throws -> (header: DTLSHandshakeHeader, body: [UInt8]) {
    let recordHeaderSize = 13
    let handshakeHeaderSize = DTLSHandshakeHeader.headerSize
    guard datagram.count >= recordHeaderSize + handshakeHeaderSize,
          datagram[0] == 22 else {
        throw TLSError.protocolFailure(reason: "Expected a DTLS handshake record")
    }

    let recordLength = (Int(datagram[11]) << 8) | Int(datagram[12])
    guard recordLength >= handshakeHeaderSize,
          recordHeaderSize + recordLength <= datagram.count,
          let messageType = DTLSHandshakeType(rawValue: datagram[recordHeaderSize]) else {
        throw TLSError.protocolFailure(reason: "Malformed DTLS record framing")
    }

    let handshakeLength =
        (Int(datagram[recordHeaderSize + 1]) << 16) |
        (Int(datagram[recordHeaderSize + 2]) << 8) |
        Int(datagram[recordHeaderSize + 3])
    let messageSequence =
        (UInt16(datagram[recordHeaderSize + 4]) << 8) |
        UInt16(datagram[recordHeaderSize + 5])
    let fragmentOffset =
        (Int(datagram[recordHeaderSize + 6]) << 16) |
        (Int(datagram[recordHeaderSize + 7]) << 8) |
        Int(datagram[recordHeaderSize + 8])
    let fragmentLength =
        (Int(datagram[recordHeaderSize + 9]) << 16) |
        (Int(datagram[recordHeaderSize + 10]) << 8) |
        Int(datagram[recordHeaderSize + 11])
    guard fragmentOffset == 0,
          fragmentLength == handshakeLength,
          recordLength >= handshakeHeaderSize + handshakeLength else {
        throw TLSError.protocolFailure(reason: "Expected one complete DTLS handshake message")
    }

    let bodyStart = recordHeaderSize + handshakeHeaderSize
    let body = Array(datagram[bodyStart..<(bodyStart + handshakeLength)])
    return (
        DTLSHandshakeHeader(
            messageType: messageType,
            length: UInt32(handshakeLength),
            messageSeq: messageSequence
        ),
        body
    )
}

private func decodeHelloVerifyRequestCookie(_ body: [UInt8]) throws -> [UInt8] {
    guard body.count >= 3 else {
        throw TLSError.protocolFailure(reason: "Truncated HelloVerifyRequest")
    }
    let cookieLength = Int(body[2])
    guard body.count == 3 + cookieLength else {
        throw TLSError.protocolFailure(reason: "Malformed HelloVerifyRequest cookie")
    }
    return Array(body[3...])
}

private func deterministicEd25519SubjectPublicKeyInfo() -> [UInt8] {
    [
        0x30, 0x2A,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x03, 0x21, 0x00,
        0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7,
        0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
        0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25,
        0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
    ]
}
