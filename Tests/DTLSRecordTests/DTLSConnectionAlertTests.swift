/// DTLS Connection Alert Tests
///
/// Tests for alert handling in DTLSConnection:
/// - close() sends close_notify alert
/// - Received close_notify sets closed state
/// - Fatal alerts set error state
/// - Operations fail after close()

import Testing
import Foundation
@testable import DTLSRecord
@testable import DTLSCore
@testable import TLSCore

@Suite("DTLS Connection Alert Tests")
struct DTLSConnectionAlertTests {

    // MARK: - close() Method

    @Test("close() marks connection as closed")
    func testCloseMarksConnectionAsClosed() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        // Start handshake (needed to use close)
        _ = try conn.startHandshake(isClient: true)

        #expect(conn.isClosed == false)

        _ = try conn.close()

        #expect(conn.isClosed == true)
    }

    @Test("close() returns alert record data")
    func testCloseReturnsAlertRecord() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        let alertData = try conn.close()

        // Alert data should contain a DTLS record
        // Minimum size: 13 (header) + 2 (alert) = 15 bytes
        #expect(alertData.count >= 15)

        // Content type should be alert (21) at the start of the record
        #expect(alertData[0] == 21)
    }

    @Test("close() can be called multiple times safely")
    func testCloseCanBeCalledMultipleTimes() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)

        _ = try conn.close()
        #expect(conn.isClosed == true)

        // Second close should still work (idempotent)
        _ = try conn.close()
        #expect(conn.isClosed == true)
    }

    // MARK: - Operations After Close

    @Test("writeApplicationData fails after close")
    func testWriteApplicationDataFailsAfterClose() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        _ = try conn.close()

        #expect(throws: DTLSConnectionError.self) {
            _ = try conn.writeApplicationData(Data([0x01, 0x02, 0x03]))
        }
    }

    @Test("processReceivedDatagram fails after close")
    func testProcessReceivedDatagramFailsAfterClose() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        _ = try conn.close()

        #expect(throws: DTLSConnectionError.self) {
            _ = try conn.processReceivedDatagram(Data([0x00, 0x01]))
        }
    }

    // MARK: - Alert Decoding

    @Test("TLSAlert.closeNotify decodes correctly")
    func testCloseNotifyDecodes() throws {
        let alertData = Data([AlertLevel.warning.rawValue, AlertDescription.closeNotify.rawValue])
        let alert = try TLSAlert.decode(from: alertData)

        #expect(alert.level == .warning)
        #expect(alert.alertDescription == .closeNotify)
    }

    @Test("TLSAlert.closeNotify encodes correctly")
    func testCloseNotifyEncodes() {
        let alert = TLSAlert.closeNotify
        let encoded = alert.encode()

        #expect(encoded.count == 2)
        #expect(encoded[0] == AlertLevel.warning.rawValue)
        #expect(encoded[1] == AlertDescription.closeNotify.rawValue)
    }

    @Test("Fatal alert decodes correctly")
    func testFatalAlertDecodes() throws {
        let alertData = Data([AlertLevel.fatal.rawValue, AlertDescription.handshakeFailure.rawValue])
        let alert = try TLSAlert.decode(from: alertData)

        #expect(alert.level == .fatal)
        #expect(alert.alertDescription == .handshakeFailure)
    }

    @Test("Alert decode fails with insufficient data")
    func testAlertDecodeFailsWithInsufficientData() {
        #expect(throws: TLSDecodeError.self) {
            _ = try TLSAlert.decode(from: Data([0x01])) // Only 1 byte
        }
    }

    // MARK: - Connection Properties

    @Test("isConnected is false before handshake completes")
    func testIsConnectedFalseBeforeHandshake() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        #expect(conn.isConnected == false)

        _ = try conn.startHandshake(isClient: true)

        #expect(conn.isConnected == false, "isConnected should be false during handshake")
    }

    @Test("isConnected is false after close")
    func testIsConnectedFalseAfterClose() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let conn = DTLSConnection(certificate: cert)

        _ = try conn.startHandshake(isClient: true)
        _ = try conn.close()

        #expect(conn.isConnected == false)
    }

    // MARK: - DTLSConnectionOutput Alert Field

    @Test("DTLSConnectionOutput can carry received alert")
    func testConnectionOutputCarriesAlert() {
        let alert = TLSAlert.closeNotify
        let output = DTLSConnectionOutput(
            datagramsToSend: [],
            applicationData: Data(),
            handshakeComplete: false,
            receivedAlert: alert
        )

        #expect(output.receivedAlert != nil)
        #expect(output.receivedAlert?.alertDescription == .closeNotify)
    }

    @Test("DTLSConnectionOutput without alert has nil")
    func testConnectionOutputWithoutAlertHasNil() {
        let output = DTLSConnectionOutput(
            datagramsToSend: [],
            applicationData: Data(),
            handshakeComplete: false
        )

        #expect(output.receivedAlert == nil)
    }

    // MARK: - Alert Static Constructors

    @Test("Common alert static constructors")
    func testCommonAlertConstructors() {
        #expect(TLSAlert.closeNotify.alertDescription == .closeNotify)
        #expect(TLSAlert.closeNotify.level == .warning)

        #expect(TLSAlert.unexpectedMessage.alertDescription == .unexpectedMessage)
        #expect(TLSAlert.unexpectedMessage.level == .fatal)

        #expect(TLSAlert.handshakeFailure.alertDescription == .handshakeFailure)
        #expect(TLSAlert.handshakeFailure.level == .fatal)

        #expect(TLSAlert.decodeError.alertDescription == .decodeError)
        #expect(TLSAlert.decodeError.level == .fatal)

        #expect(TLSAlert.internalError.alertDescription == .internalError)
        #expect(TLSAlert.internalError.level == .fatal)
    }

    // MARK: - AlertDescription Properties

    @Test("closeNotify and userCanceled are not fatal")
    func testNonFatalAlerts() {
        #expect(AlertDescription.closeNotify.isFatal == false)
        #expect(AlertDescription.userCanceled.isFatal == false)
    }

    @Test("Most alerts are fatal")
    func testMostAlertsAreFatal() {
        #expect(AlertDescription.unexpectedMessage.isFatal == true)
        #expect(AlertDescription.badRecordMac.isFatal == true)
        #expect(AlertDescription.handshakeFailure.isFatal == true)
        #expect(AlertDescription.badCertificate.isFatal == true)
        #expect(AlertDescription.decodeError.isFatal == true)
        #expect(AlertDescription.decryptError.isFatal == true)
        #expect(AlertDescription.protocolVersion.isFatal == true)
        #expect(AlertDescription.internalError.isFatal == true)
    }

    // MARK: - Error Types

    @Test("DTLSConnectionError descriptions")
    func testConnectionErrorDescriptions() {
        let errors: [DTLSConnectionError] = [
            .handshakeNotStarted,
            .handshakeNotComplete,
            .handshakeAlreadyStarted,
            .connectionClosed,
            .fatalProtocolError("test error")
        ]

        for error in errors {
            let description = error.description
            #expect(!description.isEmpty)
        }
    }

    @Test("fatalProtocolError includes reason")
    func testFatalProtocolErrorIncludesReason() {
        let error = DTLSConnectionError.fatalProtocolError("certificate expired")
        #expect(error.description.contains("certificate expired"))
    }
}
