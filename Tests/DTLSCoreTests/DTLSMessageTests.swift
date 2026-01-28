/// Tests for DTLS 1.2 message encoding/decoding

import Testing
import Foundation
@testable import DTLSCore
import TLSCore

@Suite("DTLS Message Tests")
struct DTLSMessageTests {

    // MARK: - DTLSVersion

    @Test("DTLSVersion encoding/decoding")
    func versionRoundtrip() throws {
        let version = DTLSVersion.v1_2

        var writer = TLSWriter()
        version.encode(writer: &writer)
        let data = writer.finish()

        #expect(data.count == 2)
        #expect(data[0] == 254) // 0xFE
        #expect(data[1] == 253) // 0xFD

        var reader = TLSReader(data: data)
        let decoded = try DTLSVersion.decode(reader: &reader)
        #expect(decoded == .v1_2)
    }

    @Test("DTLSVersion rawValue")
    func versionRawValue() {
        #expect(DTLSVersion.v1_2.rawValue == 0xFEFD)
        #expect(DTLSVersion.v1_0.rawValue == 0xFEFF)
    }

    // MARK: - DTLSHandshakeHeader

    @Test("Handshake header encoding/decoding")
    func handshakeHeaderRoundtrip() throws {
        let header = DTLSHandshakeHeader(
            messageType: .clientHello,
            length: 256,
            messageSeq: 1,
            fragmentOffset: 0,
            fragmentLength: 256
        )

        var writer = TLSWriter()
        header.encode(writer: &writer)
        let data = writer.finish()

        #expect(data.count == DTLSHandshakeHeader.headerSize)

        var reader = TLSReader(data: data)
        let decoded = try DTLSHandshakeHeader.decode(reader: &reader)

        #expect(decoded.messageType == .clientHello)
        #expect(decoded.length == 256)
        #expect(decoded.messageSeq == 1)
        #expect(decoded.fragmentOffset == 0)
        #expect(decoded.fragmentLength == 256)
        #expect(!decoded.isFragmented)
    }

    @Test("Fragmented header detection")
    func fragmentedHeader() {
        let header = DTLSHandshakeHeader(
            messageType: .certificate,
            length: 1000,
            messageSeq: 2,
            fragmentOffset: 0,
            fragmentLength: 500
        )
        #expect(header.isFragmented)
    }

    @Test("Encode complete handshake message")
    func encodeMessage() throws {
        let body = Data([0x01, 0x02, 0x03])
        let msg = DTLSHandshakeHeader.encodeMessage(type: .clientHello, messageSeq: 0, body: body)

        #expect(msg.count == DTLSHandshakeHeader.headerSize + body.count)

        var reader = TLSReader(data: msg)
        let header = try DTLSHandshakeHeader.decode(reader: &reader)
        #expect(header.messageType == .clientHello)
        #expect(header.length == 3)
        #expect(header.messageSeq == 0)

        let payload = try reader.readBytes(Int(header.fragmentLength))
        #expect(payload == body)
    }

    // MARK: - ClientHello

    @Test("ClientHello encoding/decoding")
    func clientHelloRoundtrip() throws {
        let original = DTLSClientHello(
            cipherSuites: [.ecdheEcdsaWithAes128GcmSha256],
            supportedGroups: [.secp256r1],
            signatureAlgorithms: [.ecdsa_secp256r1_sha256]
        )

        let encoded = original.encode()
        let decoded = try DTLSClientHello.decode(from: encoded)

        #expect(decoded.clientVersion == .v1_2)
        #expect(decoded.random.count == 32)
        #expect(decoded.cookie.isEmpty)
        #expect(decoded.cipherSuites == [.ecdheEcdsaWithAes128GcmSha256])
        #expect(decoded.supportedGroups == [.secp256r1])
        #expect(decoded.signatureAlgorithms == [.ecdsa_secp256r1_sha256])
    }

    @Test("ClientHello with cookie")
    func clientHelloWithCookie() throws {
        let cookie = Data(repeating: 0xFF, count: 32)
        let original = DTLSClientHello(
            cookie: cookie,
            cipherSuites: [.ecdheEcdsaWithAes128GcmSha256]
        )

        let encoded = original.encode()
        let decoded = try DTLSClientHello.decode(from: encoded)

        #expect(decoded.cookie == cookie)
    }

    // MARK: - ServerHello

    @Test("ServerHello encoding/decoding")
    func serverHelloRoundtrip() throws {
        let original = DTLSServerHello(cipherSuite: .ecdheEcdsaWithAes128GcmSha256)

        let encoded = original.encode()
        let decoded = try DTLSServerHello.decode(from: encoded)

        #expect(decoded.serverVersion == .v1_2)
        #expect(decoded.random.count == 32)
        #expect(decoded.cipherSuite == .ecdheEcdsaWithAes128GcmSha256)
    }

    // MARK: - HelloVerifyRequest

    @Test("HelloVerifyRequest encoding/decoding")
    func helloVerifyRequestRoundtrip() throws {
        let cookie = Data(repeating: 0xAA, count: 32)
        let original = HelloVerifyRequest(cookie: cookie)

        let encoded = original.encode()
        let decoded = try HelloVerifyRequest.decode(from: encoded)

        #expect(decoded.serverVersion == .v1_2)
        #expect(decoded.cookie == cookie)
    }

    // MARK: - ClientKeyExchange

    @Test("ClientKeyExchange encoding/decoding")
    func clientKeyExchangeRoundtrip() throws {
        let publicKey = Data(repeating: 0x42, count: 65)
        let original = ClientKeyExchange(publicKey: publicKey)

        let encoded = original.encode()
        let decoded = try ClientKeyExchange.decode(from: encoded)

        #expect(decoded.publicKey == publicKey)
    }

    // MARK: - CertificateMessage

    @Test("CertificateMessage encoding/decoding")
    func certificateMessageRoundtrip() throws {
        let cert1 = Data(repeating: 0x11, count: 100)
        let cert2 = Data(repeating: 0x22, count: 200)
        let original = CertificateMessage(certificates: [cert1, cert2])

        let encoded = original.encode()
        let decoded = try CertificateMessage.decode(from: encoded)

        #expect(decoded.certificates.count == 2)
        #expect(decoded.certificates[0] == cert1)
        #expect(decoded.certificates[1] == cert2)
    }

    // MARK: - Finished

    @Test("Finished encoding/decoding")
    func finishedRoundtrip() throws {
        let verifyData = Data(repeating: 0xEE, count: 12)
        let original = DTLSFinished(verifyData: verifyData)

        let encoded = original.encode()
        let decoded = try DTLSFinished.decode(from: encoded)

        #expect(decoded.verifyData == verifyData)
    }

    @Test("Finished rejects wrong length")
    func finishedWrongLength() {
        let data = Data(repeating: 0xEE, count: 10)
        #expect(throws: DTLSError.self) {
            try DTLSFinished.decode(from: data)
        }
    }

    // MARK: - ChangeCipherSpec

    @Test("ChangeCipherSpec encoding/decoding")
    func changeCipherSpecRoundtrip() throws {
        let original = ChangeCipherSpec()
        let encoded = original.encode()

        #expect(encoded == Data([0x01]))

        let decoded = try ChangeCipherSpec.decode(from: encoded)
        _ = decoded // no properties to check
    }

    // MARK: - ServerHelloDone

    @Test("ServerHelloDone encoding/decoding")
    func serverHelloDoneRoundtrip() throws {
        let original = ServerHelloDone()
        let encoded = original.encode()

        #expect(encoded.isEmpty)

        let decoded = try ServerHelloDone.decode(from: encoded)
        _ = decoded
    }
}
