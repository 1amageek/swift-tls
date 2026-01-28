/// Tests for DTLS Record Codec, Cryptor, and Session

import Testing
import Foundation
import Crypto
@testable import DTLSRecord
@testable import DTLSCore
import TLSCore

@Suite("DTLSRecord Codec Tests")
struct DTLSRecordCodecTests {

    @Test("Record encoding/decoding roundtrip")
    func recordRoundtrip() throws {
        let payload = Data("hello dtls".utf8)
        let record = DTLSRecord(
            contentType: .handshake,
            epoch: 0,
            sequenceNumber: 42,
            fragment: payload
        )

        let encoded = record.encode()
        #expect(encoded.count == DTLSRecord.headerSize + payload.count)

        let (decoded, consumed) = try #require(try DTLSRecord.decode(from: encoded))
        #expect(consumed == encoded.count)
        #expect(decoded.contentType == .handshake)
        #expect(decoded.version == .v1_2)
        #expect(decoded.epoch == 0)
        #expect(decoded.sequenceNumber == 42)
        #expect(decoded.fragment == payload)
    }

    @Test("Record with epoch 1")
    func recordEpoch1() throws {
        let record = DTLSRecord(
            contentType: .applicationData,
            epoch: 1,
            sequenceNumber: 100,
            fragment: Data([0x01, 0x02, 0x03])
        )

        let encoded = record.encode()
        let (decoded, _) = try #require(try DTLSRecord.decode(from: encoded))

        #expect(decoded.epoch == 1)
        #expect(decoded.sequenceNumber == 100)
    }

    @Test("Record returns nil for insufficient data")
    func insufficientData() throws {
        let data = Data(repeating: 0, count: 5) // Less than header size
        let result = try DTLSRecord.decode(from: data)
        #expect(result == nil)
    }

    @Test("AAD construction")
    func aadConstruction() {
        let record = DTLSRecord(
            contentType: .applicationData,
            epoch: 1,
            sequenceNumber: 5,
            fragment: Data()
        )

        let aad = record.buildAAD(plaintextLength: 100)
        // epoch (2) + seq_num (6) + content_type (1) + version (2) + length (2) = 13 bytes
        #expect(aad.count == 13)
    }
}

@Suite("DTLSRecord Cryptor Tests")
struct DTLSRecordCryptorTests {

    @Test("AEAD seal/open roundtrip")
    func aeadRoundtrip() throws {
        let key = SymmetricKey(size: .bits128)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let plaintext = Data("hello world".utf8)
        let aad = Data(repeating: 0x03, count: 13)

        let ciphertext = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: key,
            fixedIV: fixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad
        )

        // explicit_nonce (8) + ciphertext (11) + tag (16) = 35
        #expect(ciphertext.count == 8 + plaintext.count + 16)

        let decrypted = try DTLSRecordCryptor.open(
            ciphertext: ciphertext,
            key: key,
            fixedIV: fixedIV,
            additionalData: aad
        )

        #expect(decrypted == plaintext)
    }

    @Test("AEAD detects tampered ciphertext")
    func aeadTamperDetection() throws {
        let key = SymmetricKey(size: .bits128)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let plaintext = Data("secret data".utf8)
        let aad = Data(repeating: 0x03, count: 13)

        var ciphertext = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: key,
            fixedIV: fixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad
        )

        // Tamper with ciphertext
        ciphertext[10] ^= 0xFF

        #expect(throws: (any Error).self) {
            try DTLSRecordCryptor.open(
                ciphertext: ciphertext,
                key: key,
                fixedIV: fixedIV,
                additionalData: aad
            )
        }
    }

    @Test("AEAD detects tampered AAD")
    func aeadAADTamperDetection() throws {
        let key = SymmetricKey(size: .bits128)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let plaintext = Data("secret".utf8)
        let aad = Data(repeating: 0x03, count: 13)

        let ciphertext = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: key,
            fixedIV: fixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad
        )

        // Use different AAD for decryption
        let wrongAAD = Data(repeating: 0x04, count: 13)

        #expect(throws: (any Error).self) {
            try DTLSRecordCryptor.open(
                ciphertext: ciphertext,
                key: key,
                fixedIV: fixedIV,
                additionalData: wrongAAD
            )
        }
    }

    @Test("AEAD with wrong key fails")
    func aeadWrongKey() throws {
        let key1 = SymmetricKey(size: .bits128)
        let key2 = SymmetricKey(size: .bits128)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let plaintext = Data("data".utf8)
        let aad = Data(repeating: 0x03, count: 13)

        let ciphertext = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: key1,
            fixedIV: fixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad
        )

        #expect(throws: (any Error).self) {
            try DTLSRecordCryptor.open(
                ciphertext: ciphertext,
                key: key2,
                fixedIV: fixedIV,
                additionalData: aad
            )
        }
    }

    @Test("AEAD with 256-bit key")
    func aead256BitKey() throws {
        let key = SymmetricKey(size: .bits256)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let plaintext = Data("256-bit encryption test".utf8)
        let aad = Data(repeating: 0x03, count: 13)

        let ciphertext = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: key,
            fixedIV: fixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad
        )

        let decrypted = try DTLSRecordCryptor.open(
            ciphertext: ciphertext,
            key: key,
            fixedIV: fixedIV,
            additionalData: aad
        )

        #expect(decrypted == plaintext)
    }
}

@Suite("DTLSSession Tests")
struct DTLSSessionTests {

    @Test("Session encrypt/decrypt roundtrip")
    func sessionRoundtrip() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let remoteCertDER = try DTLSCertificate.generateSelfSigned().derEncoded

        let keyBlock = DTLSKeyBlock(
            clientWriteKey: Data(repeating: 0x01, count: 16),
            serverWriteKey: Data(repeating: 0x02, count: 16),
            clientWriteIV: Data(repeating: 0x03, count: 4),
            serverWriteIV: Data(repeating: 0x04, count: 4)
        )

        var clientSession = DTLSSession(
            localCertificate: cert,
            remoteCertificateDER: remoteCertDER,
            cipherSuite: .ecdheEcdsaWithAes128GcmSha256,
            keyBlock: keyBlock,
            isClient: true
        )

        let serverSession = DTLSSession(
            localCertificate: cert,
            remoteCertificateDER: remoteCertDER,
            cipherSuite: .ecdheEcdsaWithAes128GcmSha256,
            keyBlock: keyBlock,
            isClient: false
        )

        let plaintext = Data("Hello from client".utf8)
        let encrypted = try clientSession.encrypt(plaintext)

        let decrypted = try serverSession.decrypt(encrypted)
        #expect(decrypted == plaintext)
    }

    @Test("Session fingerprint verification")
    func fingerprintVerification() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let remoteCert = try DTLSCertificate.generateSelfSigned()

        let keyBlock = DTLSKeyBlock(
            clientWriteKey: Data(repeating: 0x01, count: 16),
            serverWriteKey: Data(repeating: 0x02, count: 16),
            clientWriteIV: Data(repeating: 0x03, count: 4),
            serverWriteIV: Data(repeating: 0x04, count: 4)
        )

        let session = DTLSSession(
            localCertificate: cert,
            remoteCertificateDER: remoteCert.derEncoded,
            cipherSuite: .ecdheEcdsaWithAes128GcmSha256,
            keyBlock: keyBlock,
            isClient: true
        )

        #expect(session.remoteFingerprint == remoteCert.fingerprint)
    }
}
