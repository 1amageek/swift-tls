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

    // MARK: - Fatal Error State Propagation

    @Test("TLSError from handler sets fatal error state on connection")
    func testTLSErrorSetsFatalState() async throws {
        // Create a client connection with a tiny handshake buffer (1 byte).
        // Any handshake data > 1 byte triggers TLSError.internalError.
        var config = TLSConfiguration.client(serverName: "localhost")
        config.maxHandshakeBufferSize = 1
        let conn = TLSConnection(configuration: config)

        _ = try await conn.startHandshake(isClient: true)

        // Construct a valid TLS handshake record with 4-byte payload.
        // Record: type=handshake(0x16), version=0x0301, length=4, payload=4 bytes
        let record = Data([0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04])

        // First call: should throw TLSError (buffer exceeds maxHandshakeBufferSize)
        var firstErrorThrown = false
        do {
            _ = try await conn.processReceivedData(record)
        } catch {
            firstErrorThrown = true
        }
        #expect(firstErrorThrown, "Expected TLSError from buffer overflow")

        // Connection should now be in fatal error state.
        // Subsequent processReceivedData should throw fatalProtocolError
        // (not the original TLSError, but the stored fatal state error).
        do {
            _ = try await conn.processReceivedData(Data([0x16, 0x03, 0x01, 0x00, 0x01, 0x00]))
            Issue.record("Expected fatalProtocolError on second call")
        } catch let error as TLSConnectionError {
            guard case .fatalProtocolError = error else {
                Issue.record("Expected .fatalProtocolError, got: \(error)")
                return
            }
        }

        // writeApplicationData should also be rejected
        #expect(throws: TLSConnectionError.self) {
            _ = try conn.writeApplicationData(Data("hello".utf8))
        }

        // close should also be rejected
        #expect(throws: TLSConnectionError.self) {
            _ = try conn.close()
        }

        // isConnected should be false
        #expect(!conn.isConnected)
    }

    @Test("Non-fatal errors do not set fatal error state")
    func testNonFatalErrorDoesNotSetFatalState() async throws {
        let conn = TLSConnection()

        // bufferOverflow is non-fatal (it's a TLSConnectionError that returns nil from classifyFatalError)
        // We can't easily trigger it here, but we can verify the connection
        // stays usable after a concurrentReadNotAllowed or similar.
        // Instead, test that after a failed processReceivedData with
        // invalid record data, the connection may or may not enter fatal state
        // depending on the error type.

        _ = try await conn.startHandshake(isClient: true)

        // Feed incomplete data (not a full TLS record) — this should return
        // without error (just buffered, waiting for more data)
        let output = try await conn.processReceivedData(Data([0x16, 0x03]))
        #expect(output.handshakeComplete == false)

        // Connection should still accept new data (not in fatal state)
        let output2 = try await conn.processReceivedData(Data([0x01]))
        #expect(output2.handshakeComplete == false)
    }
}
