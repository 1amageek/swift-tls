/// TLS Connection Tests
///
/// Tests the high-level TLSConnection API for TCP consumers.

import Testing
import Foundation
import Crypto

@testable import TLSRecord
@testable import TLSCore

@Suite("TLS Connection Tests")
struct TLSConnectionTests {

    private static let testSigningKey = SigningKey.generateP256()
    private static let testCertificateChain = [Data([0x30, 0x82, 0x01, 0x00])]

    // MARK: - Initialization

    @Test("TLSConnection initializes with default configuration")
    func defaultInit() {
        let conn = TLSConnection()
        #expect(conn.isConnected == false)
        #expect(conn.negotiatedALPN == nil)
    }

    @Test("TLSConnection initializes with custom configuration")
    func customInit() {
        let config = TLSConfiguration.client(
            serverName: "example.com",
            alpnProtocols: ["h2"]
        )
        let conn = TLSConnection(configuration: config)
        #expect(conn.isConnected == false)
    }

    // MARK: - Handshake Start

    @Test("Client starts handshake and produces data")
    func clientStartHandshake() async throws {
        let config = TLSConfiguration.client(serverName: "localhost")
        let conn = TLSConnection(configuration: config)

        let data = try await conn.startHandshake(isClient: true)

        // Should have produced TLS record(s) with ClientHello
        #expect(!data.isEmpty)

        // First byte should be handshake content type (22)
        #expect(data[0] == TLSContentType.handshake.rawValue)

        // Not connected yet
        #expect(conn.isConnected == false)
    }

    @Test("Server starts handshake with empty output")
    func serverStartHandshake() async throws {
        var config = TLSConfiguration()
        config.signingKey = Self.testSigningKey
        config.certificateChain = Self.testCertificateChain
        let conn = TLSConnection(configuration: config)

        let data = try await conn.startHandshake(isClient: false)

        // Server produces no data until it receives ClientHello
        #expect(data.isEmpty)
        #expect(conn.isConnected == false)
    }

    // MARK: - Pre-Handshake Errors

    @Test("writeApplicationData before handshake throws")
    func writeBeforeHandshake() throws {
        let conn = TLSConnection()

        #expect(throws: TLSConnectionError.self) {
            _ = try conn.writeApplicationData(Data("hello".utf8))
        }
    }

    // MARK: - Close

    @Test("Close produces close_notify alert")
    func closeProducesAlert() throws {
        let conn = TLSConnection()

        let closeData = try conn.close()
        #expect(!closeData.isEmpty)

        // Should be an alert record
        #expect(closeData[0] == TLSContentType.alert.rawValue)
    }

    @Test("After close, isConnected is false")
    func closeDisconnects() throws {
        let conn = TLSConnection()
        _ = try conn.close()
        #expect(conn.isConnected == false)
    }

    // MARK: - TLSConnectionOutput

    @Test("TLSConnectionOutput default values")
    func outputDefaults() {
        let output = TLSConnectionOutput()
        #expect(output.dataToSend.isEmpty)
        #expect(output.applicationData.isEmpty)
        #expect(output.handshakeComplete == false)
        #expect(output.alert == nil)
    }

    @Test("TLSConnectionOutput with values")
    func outputWithValues() {
        let output = TLSConnectionOutput(
            dataToSend: Data([0x01]),
            applicationData: Data([0x02]),
            handshakeComplete: true,
            alert: .closeNotify
        )
        #expect(output.dataToSend == Data([0x01]))
        #expect(output.applicationData == Data([0x02]))
        #expect(output.handshakeComplete == true)
        #expect(output.alert?.alertDescription == .closeNotify)
    }
}
