/// DTLS 1.2 Connection (RFC 6347)
///
/// High-level API that integrates the handshake handler, record layer,
/// and flight controller into a unified connection interface.
///
/// ## RFC Compliance
///
/// - **RFC 6347 §4.1.2.6**: Replayed/too-old records are silently discarded,
///   but datagram processing continues to subsequent records
/// - **RFC 6347 §4.1**: Epoch mismatch records are silently discarded
/// - **RFC 5246 §7.2**: After `close_notify` or fatal alert, subsequent
///   records in the same datagram are not processed
///
/// ## Usage
///
/// ```swift
/// let cert = try DTLSCertificate()
/// let conn = DTLSConnection(certificate: cert)
///
/// // Client: start handshake
/// let datagrams = try conn.startHandshake(isClient: true)
/// send(datagrams)
///
/// // Process received UDP datagrams
/// let output = try conn.processReceivedDatagram(received)
/// send(output.datagramsToSend)
/// if output.handshakeComplete { ... }
///
/// // Send application data
/// let encrypted = try conn.writeApplicationData(plaintext)
/// send([encrypted])
/// ```

import Foundation
import Synchronization
import Crypto
import DTLSCore
import TLSCore

// MARK: - Output Type

/// Output from processing a received datagram
public struct DTLSConnectionOutput: Sendable {
    /// Encoded DTLS datagrams to send to the peer
    public let datagramsToSend: [Data]

    /// Decrypted application data received from the peer
    public let applicationData: Data

    /// Whether the handshake just completed
    public let handshakeComplete: Bool

    /// Alert received from peer (if any)
    public let receivedAlert: TLSAlert?

    public init(
        datagramsToSend: [Data] = [],
        applicationData: Data = Data(),
        handshakeComplete: Bool = false,
        receivedAlert: TLSAlert? = nil
    ) {
        self.datagramsToSend = datagramsToSend
        self.applicationData = applicationData
        self.handshakeComplete = handshakeComplete
        self.receivedAlert = receivedAlert
    }
}

// MARK: - Error Type

/// Errors from DTLSConnection operations
public enum DTLSConnectionError: Error, Sendable {
    case handshakeNotStarted
    case handshakeNotComplete
    case handshakeAlreadyStarted
    case connectionClosed
    case fatalProtocolError(String)
}

extension DTLSConnectionError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .handshakeNotStarted:
            return "Handshake not started"
        case .handshakeNotComplete:
            return "Handshake not complete"
        case .handshakeAlreadyStarted:
            return "Handshake already started"
        case .connectionClosed:
            return "Connection closed"
        case .fatalProtocolError(let reason):
            return "Fatal protocol error: \(reason)"
        }
    }
}

// MARK: - DTLSConnection

/// A DTLS 1.2 connection managing handshake and record-layer encryption
public final class DTLSConnection: Sendable {
    private let certificate: DTLSCertificate
    private let supportedCipherSuites: [DTLSCipherSuite]
    private let recordLayer: DTLSRecordLayer
    private let flightController: FlightController
    private let state: Mutex<ConnectionState>

    private struct ConnectionState: Sendable {
        var handshakeStarted: Bool = false
        var handshakeCompleted: Bool = false
        var isClient: Bool = false
        var clientHandler: DTLSClientHandshakeHandler?
        var serverHandler: DTLSServerHandshakeHandler?
        var pendingKeyBlock: DTLSKeyBlock?
        var expectingCCS: Bool = false
        var remoteCertificateDER: Data?
        var negotiatedCipherSuite: DTLSCipherSuite?

        // Connection closure state
        var closed: Bool = false
        var fatalError: DTLSConnectionError?
    }

    public init(
        certificate: DTLSCertificate,
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256]
    ) {
        self.certificate = certificate
        self.supportedCipherSuites = supportedCipherSuites
        self.recordLayer = DTLSRecordLayer()
        self.flightController = FlightController()
        self.state = Mutex(ConnectionState())
    }

    // MARK: - Public API

    /// Start the DTLS handshake
    ///
    /// - Parameter isClient: `true` for client mode, `false` for server mode
    /// - Returns: Datagrams to send (ClientHello for client, empty for server)
    public func startHandshake(isClient: Bool) throws -> [Data] {
        let actions: [DTLSHandshakeAction] = try state.withLock { s in
            guard !s.handshakeStarted else {
                throw DTLSConnectionError.handshakeAlreadyStarted
            }
            s.handshakeStarted = true
            s.isClient = isClient

            if isClient {
                let handler = DTLSClientHandshakeHandler(
                    certificate: certificate,
                    supportedCipherSuites: supportedCipherSuites
                )
                s.clientHandler = handler
                return handler.startHandshake()
            } else {
                let handler = DTLSServerHandshakeHandler(
                    certificate: certificate,
                    supportedCipherSuites: supportedCipherSuites
                )
                s.serverHandler = handler
                return []
            }
        }

        let datagrams = try processActions(actions)

        // Register flight for retransmission
        if !datagrams.isEmpty {
            flightController.startFlight(.clientHello, messages: datagrams)
        }

        return datagrams
    }

    /// Process a received UDP datagram
    ///
    /// Decodes all DTLS records in the datagram, processes handshake messages,
    /// handles ChangeCipherSpec transitions, and decrypts application data.
    ///
    /// - Parameters:
    ///   - data: Raw UDP datagram bytes
    ///   - remoteAddress: Client's transport address (used for cookie verification on server)
    /// - Returns: Datagrams to send and any received application data
    public func processReceivedDatagram(
        _ data: Data,
        remoteAddress: Data = Data()
    ) throws -> DTLSConnectionOutput {
        // Check connection state
        try state.withLock { s in
            if let err = s.fatalError { throw err }
            if s.closed { throw DTLSConnectionError.connectionClosed }
        }

        // Get handler references (quick lock, then release)
        let (isClient, clientHandler, serverHandler) = state.withLock { s in
            (s.isClient, s.clientHandler, s.serverHandler)
        }

        guard clientHandler != nil || serverHandler != nil else {
            throw DTLSConnectionError.handshakeNotStarted
        }

        var allDatagrams: [Data] = []
        var applicationData = Data()
        var handshakeComplete = false
        var receivedAlert: TLSAlert?

        // Cancel pending retransmission on receiving any data
        flightController.responseReceived()

        // Parse all records from the datagram
        var offset = 0
        recordLoop: while offset < data.count {
            let remaining = Data(data[data.startIndex.advanced(by: offset)...])

            // Decode record with proper handling of replay detection
            // RFC 6347 §4.1.2.6: Replayed records should be silently discarded,
            // but datagram processing continues to subsequent records
            let decodeResult = try recordLayer.decodeRecord(from: remaining)

            let record: DTLSRecord
            switch decodeResult {
            case .record(let r, let consumed):
                record = r
                offset += consumed

            case .insufficientData:
                // No more complete records in this datagram
                break recordLoop

            case .discarded(let consumed, _):
                // Record was replayed or too old - skip and continue to next record
                offset += consumed
                continue recordLoop
            }

            switch record.contentType {
            case .handshake:
                let actions: [DTLSHandshakeAction]

                // Route ClientHello to the dedicated server method
                if let firstByte = record.fragment.first,
                   firstByte == DTLSHandshakeType.clientHello.rawValue,
                   !isClient,
                   let handler = serverHandler {
                    actions = try handler.processClientHello(
                        record.fragment,
                        clientAddress: remoteAddress
                    )
                } else if isClient, let handler = clientHandler {
                    actions = try handler.processHandshakeMessage(record.fragment)
                } else if let handler = serverHandler {
                    actions = try handler.processHandshakeMessage(record.fragment)
                } else {
                    throw DTLSConnectionError.handshakeNotStarted
                }

                let datagrams = try processActions(actions)
                allDatagrams.append(contentsOf: datagrams)

                // Check if handshake just completed
                if actions.contains(where: { if case .handshakeComplete = $0 { return true } else { return false } }) {
                    handshakeComplete = true
                    finalizeHandshake(isClient: isClient, clientHandler: clientHandler, serverHandler: serverHandler)
                }

            case .changeCipherSpec:
                // Install read keys from pending key block
                installReadKeys()

                // Notify the handler
                if isClient {
                    try clientHandler?.processChangeCipherSpec()
                } else {
                    try serverHandler?.processChangeCipherSpec()
                }

            case .applicationData:
                applicationData.append(record.fragment)

            case .alert:
                // Decode and handle alert
                // Per RFC 6347, malformed alerts are discarded (no exception thrown to caller)
                // but we track that we received an alert we couldn't process
                do {
                    let alert = try TLSAlert.decode(from: record.fragment)
                    receivedAlert = alert

                    if alert.alertDescription == .closeNotify {
                        state.withLock { $0.closed = true }
                        // Stop processing immediately - data after close_notify is untrusted
                        return DTLSConnectionOutput(
                            datagramsToSend: allDatagrams,
                            applicationData: applicationData,
                            handshakeComplete: handshakeComplete,
                            receivedAlert: alert
                        )
                    } else if alert.level == .fatal {
                        let err = DTLSConnectionError.fatalProtocolError(alert.alertDescription.description)
                        state.withLock { $0.fatalError = err }
                        // Stop processing immediately - fatal alert terminates connection
                        return DTLSConnectionOutput(
                            datagramsToSend: allDatagrams,
                            applicationData: applicationData,
                            handshakeComplete: handshakeComplete,
                            receivedAlert: alert
                        )
                    }
                } catch {
                    // Malformed alert received - this is a protocol violation but we don't
                    // crash the connection. The record is discarded per DTLS robustness principle.
                }
            }
        }

        // Register response flight for retransmission
        if !allDatagrams.isEmpty {
            let flight = inferFlight(isClient: isClient, handshakeComplete: handshakeComplete)
            flightController.startFlight(flight, messages: allDatagrams)
        }

        return DTLSConnectionOutput(
            datagramsToSend: allDatagrams,
            applicationData: applicationData,
            handshakeComplete: handshakeComplete,
            receivedAlert: receivedAlert
        )
    }

    /// Encrypt application data for sending
    ///
    /// - Parameter data: Plaintext application data
    /// - Returns: Encoded DTLS datagram containing the encrypted record
    public func writeApplicationData(_ data: Data) throws -> Data {
        // Check connection state
        try state.withLock { s in
            if let err = s.fatalError { throw err }
            if s.closed { throw DTLSConnectionError.connectionClosed }
            guard s.handshakeCompleted else {
                throw DTLSConnectionError.handshakeNotComplete
            }
        }
        return try recordLayer.encodeRecord(
            contentType: .applicationData,
            plaintext: data
        )
    }

    /// Close the connection gracefully by sending close_notify alert
    ///
    /// - Returns: Encoded DTLS datagram containing the close_notify alert
    public func close() throws -> Data {
        state.withLock { $0.closed = true }
        let alertData = TLSAlert.closeNotify.encode()
        return try recordLayer.encodeRecord(
            contentType: .alert,
            plaintext: alertData
        )
    }

    /// Handle retransmission timeout
    ///
    /// Call this when the retransmission timer fires.
    ///
    /// - Returns: Datagrams to retransmit
    public func handleTimeout() throws -> [Data] {
        try flightController.retransmit()
    }

    // MARK: - Properties

    /// Whether the handshake is complete and the connection is ready
    public var isConnected: Bool {
        state.withLock { $0.handshakeCompleted && !$0.closed }
    }

    /// Whether the connection has been closed
    public var isClosed: Bool {
        state.withLock { $0.closed }
    }

    /// The remote peer's DER-encoded certificate
    public var remoteCertificateDER: Data? {
        state.withLock { $0.remoteCertificateDER }
    }

    /// The remote peer's certificate fingerprint
    public var remoteFingerprint: CertificateFingerprint? {
        guard let der = remoteCertificateDER else { return nil }
        return CertificateFingerprint.fromDER(der)
    }

    /// The negotiated cipher suite
    public var negotiatedCipherSuite: DTLSCipherSuite? {
        state.withLock { $0.negotiatedCipherSuite }
    }

    /// The current retransmission timeout
    public var retransmissionTimeout: Duration {
        flightController.timeout
    }

    /// Whether there is a pending flight awaiting response
    public var isAwaitingResponse: Bool {
        flightController.isAwaitingResponse
    }

    // MARK: - Private

    /// Process handshake actions into encoded DTLS datagrams
    private func processActions(_ actions: [DTLSHandshakeAction]) throws -> [Data] {
        guard !actions.isEmpty else { return [] }

        var recordBytes: [Data] = []

        for action in actions {
            switch action {
            case .sendMessage(let msg):
                let encoded = try recordLayer.encodeRecord(
                    contentType: .handshake,
                    plaintext: msg
                )
                recordBytes.append(encoded)

            case .sendChangeCipherSpec:
                let encoded = try recordLayer.encodeRecord(
                    contentType: .changeCipherSpec,
                    plaintext: Data([0x01])
                )
                recordBytes.append(encoded)
                // Install write keys after encoding CCS at the old epoch
                installWriteKeys()

            case .keysAvailable(let keyBlock, let cipherSuite):
                state.withLock { s in
                    s.pendingKeyBlock = keyBlock
                    s.negotiatedCipherSuite = cipherSuite
                }

            case .expectChangeCipherSpec:
                state.withLock { s in
                    s.expectingCCS = true
                }

            case .handshakeComplete:
                // Handled by caller after processActions returns
                break
            }
        }

        // Pack all records into a single datagram
        guard !recordBytes.isEmpty else { return [] }
        var datagram = Data()
        for record in recordBytes {
            datagram.append(record)
        }
        return [datagram]
    }

    /// Install write keys from the pending key block
    private func installWriteKeys() {
        let (isClient, keyBlock) = state.withLock { s in
            (s.isClient, s.pendingKeyBlock)
        }
        guard let kb = keyBlock else { return }

        if isClient {
            recordLayer.setWriteKeys(
                key: SymmetricKey(data: kb.clientWriteKey),
                fixedIV: kb.clientWriteIV
            )
        } else {
            recordLayer.setWriteKeys(
                key: SymmetricKey(data: kb.serverWriteKey),
                fixedIV: kb.serverWriteIV
            )
        }
    }

    /// Install read keys from the pending key block
    private func installReadKeys() {
        let (isClient, keyBlock) = state.withLock { s in
            (s.isClient, s.pendingKeyBlock)
        }
        guard let kb = keyBlock else { return }

        if isClient {
            recordLayer.setReadKeys(
                key: SymmetricKey(data: kb.serverWriteKey),
                fixedIV: kb.serverWriteIV
            )
        } else {
            recordLayer.setReadKeys(
                key: SymmetricKey(data: kb.clientWriteKey),
                fixedIV: kb.clientWriteIV
            )
        }
    }

    /// Finalize handshake state after completion
    private func finalizeHandshake(
        isClient: Bool,
        clientHandler: DTLSClientHandshakeHandler?,
        serverHandler: DTLSServerHandshakeHandler?
    ) {
        state.withLock { s in
            s.handshakeCompleted = true
            if isClient {
                s.remoteCertificateDER = clientHandler?.serverCertificateDER
                s.negotiatedCipherSuite = clientHandler?.negotiatedCipherSuite
            } else {
                s.remoteCertificateDER = serverHandler?.clientCertificateDER
                s.negotiatedCipherSuite = serverHandler?.negotiatedCipherSuite
            }
        }
    }

    /// Infer the flight type for retransmission tracking
    private func inferFlight(isClient: Bool, handshakeComplete: Bool) -> DTLSFlight {
        if handshakeComplete {
            return isClient ? .clientKeyExchangeToFinished : .serverChangeCipherSpecFinished
        }
        return isClient ? .clientHello : .serverHelloToCertDone
    }
}
