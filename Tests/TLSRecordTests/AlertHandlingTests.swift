/// TLS Alert Handling Tests
///
/// Tests alert encoding/decoding, plaintext vs encrypted alert routing,
/// and post-encryption rejection of plaintext records (RFC 8446 Section 5).

import Testing
import Foundation
import Crypto
@testable import TLSRecord
@testable import TLSCore

@Suite("TLS Alert Handling Tests")
struct AlertHandlingTests {

    @Test("Plaintext alert before encryption has content type 21")
    func testPlaintextAlertBeforeEncryption() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let alertRecord = try layer.writeAlert(.closeNotify)

        // Content type byte should be 21 (alert) when no send keys are active
        #expect(alertRecord[0] == TLSContentType.alert.rawValue)
        #expect(alertRecord[0] == 21)
    }

    @Test("Encrypted alert after key activation has content type 23")
    func testEncryptedAlertAfterKeyActivation() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        layer.updateSendKeys(keys)

        let alertRecord = try layer.writeAlert(.closeNotify)

        // After send keys are active, alert must be wrapped in applicationData (23)
        #expect(alertRecord[0] == TLSContentType.applicationData.rawValue)
        #expect(alertRecord[0] == 23)
    }

    @Test("Decrypt encrypted alert through record layer")
    func testDecryptEncryptedAlert() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        layer.updateKeys(send: keys, receive: keys)

        // Encrypt a close_notify alert using the cryptor via the layer
        let encrypted = try layer.writeAlert(.closeNotify)

        // Process the encrypted record back through the same layer
        let outputs = try layer.processReceivedData(encrypted)
        #expect(outputs.count == 1)

        if case .alert(let alert) = outputs[0] {
            #expect(alert.alertDescription == .closeNotify)
            #expect(alert.level == .warning)
        } else {
            Issue.record("Expected .alert output but got \(outputs[0])")
        }
    }

    @Test("Plaintext alert rejected after encryption is active")
    func testPlaintextAlertRejectedAfterEncryption() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        layer.updateReceiveKeys(keys)

        // Construct a plaintext alert record manually (content type 21)
        let alertData = TLSAlert.closeNotify.encode()
        let plaintextAlertRecord = TLSRecordCodec.encodePlaintext(type: .alert, data: alertData)

        // Should throw unexpectedPlaintextAlert because receive encryption is active
        #expect(throws: TLSRecordError.self) {
            _ = try layer.processReceivedData(plaintextAlertRecord)
        }
    }

    @Test("Plaintext handshake rejected after encryption is active")
    func testPlaintextHandshakeRejectedAfterEncryption() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        let secret = SymmetricKey(size: .bits256)
        let keys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        layer.updateReceiveKeys(keys)

        // Construct a plaintext handshake record (content type 22)
        let handshakeData = Data([0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00])
        let plaintextHandshakeRecord = TLSRecordCodec.encodePlaintext(type: .handshake, data: handshakeData)

        // Should throw unexpectedPlaintextHandshake because receive encryption is active
        #expect(throws: TLSRecordError.self) {
            _ = try layer.processReceivedData(plaintextHandshakeRecord)
        }
    }

    @Test("Plaintext applicationData rejected before encryption is active")
    func testPlaintextApplicationDataRejectedBeforeEncryption() throws {
        let layer = TLSRecordLayer(cipherSuite: .tls_aes_128_gcm_sha256)

        // Do NOT activate any keys — receive encryption is NOT active

        // Construct an applicationData record (content type 23) without encryption
        let appData = Data("hello".utf8)
        let plaintextAppDataRecord = TLSRecordCodec.encodePlaintext(type: .applicationData, data: appData)

        // Should throw unexpectedPlaintextApplicationData because encryption is not active
        #expect(throws: TLSRecordError.self) {
            _ = try layer.processReceivedData(plaintextAppDataRecord)
        }
    }

    @Test("Close notify alert encoding and decoding roundtrip")
    func testCloseNotifyAlert() throws {
        let original = TLSAlert.closeNotify

        // Verify expected field values
        #expect(original.level == .warning)
        #expect(original.alertDescription == .closeNotify)

        // Encode
        let encoded = original.encode()
        #expect(encoded.count == 2)
        #expect(encoded[0] == AlertLevel.warning.rawValue)
        #expect(encoded[1] == AlertDescription.closeNotify.rawValue)

        // Decode
        let decoded = try TLSAlert.decode(from: encoded)
        #expect(decoded == original)
        #expect(decoded.level == .warning)
        #expect(decoded.alertDescription == .closeNotify)
    }

    @Test("TLSHandshakeError.toAlert returns correct AlertDescription")
    func testAlertErrorMapping() {
        // unexpectedMessage -> unexpectedMessage
        let unexpectedMsg = TLSHandshakeError.unexpectedMessage("test")
        #expect(unexpectedMsg.toAlert.alertDescription == .unexpectedMessage)

        // unsupportedVersion -> protocolVersion
        let unsupportedVer = TLSHandshakeError.unsupportedVersion
        #expect(unsupportedVer.toAlert.alertDescription == .protocolVersion)

        // noCipherSuiteMatch -> handshakeFailure
        let noCipher = TLSHandshakeError.noCipherSuiteMatch
        #expect(noCipher.toAlert.alertDescription == .handshakeFailure)

        // noALPNMatch -> noApplicationProtocol
        let noALPN = TLSHandshakeError.noALPNMatch
        #expect(noALPN.toAlert.alertDescription == .noApplicationProtocol)

        // certificateVerificationFailed -> badCertificate
        let badCert = TLSHandshakeError.certificateVerificationFailed("invalid")
        #expect(badCert.toAlert.alertDescription == .badCertificate)

        // signatureVerificationFailed -> decryptError
        let sigFail = TLSHandshakeError.signatureVerificationFailed
        #expect(sigFail.toAlert.alertDescription == .decryptError)

        // internalError -> internalError
        let internalErr = TLSHandshakeError.internalError("something went wrong")
        #expect(internalErr.toAlert.alertDescription == .internalError)

        // certificateRequired -> certificateRequired
        let certRequired = TLSHandshakeError.certificateRequired
        #expect(certRequired.toAlert.alertDescription == .certificateRequired)
    }
}
