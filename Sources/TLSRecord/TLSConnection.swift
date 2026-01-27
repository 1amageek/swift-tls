/// TLS 1.3 Connection (High-Level API)
///
/// Combines TLS handshake (TLSHandshakeProvider) with record-layer framing
/// and AEAD encryption to provide a complete TLS connection for TCP consumers.
///
/// Usage:
/// 1. Create a TLSConnection with configuration
/// 2. Call startHandshake() and send the returned bytes over TCP
/// 3. Feed TCP data into processReceivedData() and send returned bytes
/// 4. After handshake completes, use writeApplicationData() to encrypt outgoing data
/// 5. Call close() to gracefully terminate

import Foundation
import Synchronization
import TLSCore

// MARK: - TLS Connection Output

/// Output from processing received TCP data
public struct TLSConnectionOutput: Sendable {
    /// Data to send back over TCP (handshake messages, encrypted responses)
    public let dataToSend: Data

    /// Decrypted application data received from the peer
    public let applicationData: Data

    /// Whether the handshake just completed during this processing
    public let handshakeComplete: Bool

    /// Alert received from the peer (if any)
    public let alert: TLSAlert?

    public init(
        dataToSend: Data = Data(),
        applicationData: Data = Data(),
        handshakeComplete: Bool = false,
        alert: TLSAlert? = nil
    ) {
        self.dataToSend = dataToSend
        self.applicationData = applicationData
        self.handshakeComplete = handshakeComplete
        self.alert = alert
    }
}

// MARK: - TLS Connection

/// High-level TLS 1.3 connection for TCP consumers.
///
/// This class integrates the TLS handshake state machine with record-layer
/// framing and AEAD encryption to provide a complete TLS session over TCP.
///
/// Unlike ``TLSRecordLayer`` (which requires external key management),
/// this class automatically manages encryption keys as the handshake progresses,
/// processing records one at a time with interleaved key derivation.
public final class TLSConnection: Sendable {

    private let handler: TLS13Handler
    private let connectionState: Mutex<ConnectionState>

    // MARK: - Initialization

    /// Creates a new TLS connection
    /// - Parameter configuration: The TLS configuration
    public init(configuration: TLSConfiguration = TLSConfiguration()) {
        self.handler = TLS13Handler(configuration: configuration)
        self.connectionState = Mutex(ConnectionState())
    }

    // MARK: - Public API

    /// Start the TLS handshake.
    ///
    /// - Parameter isClient: true for client mode, false for server mode
    /// - Returns: Data to send over TCP (ClientHello for clients, empty for servers)
    public func startHandshake(isClient: Bool) async throws -> Data {
        let outputs = try await handler.startHandshake(isClient: isClient)

        connectionState.withLock { state in
            state.handshakeStarted = true
        }

        return try encodeOutputs(outputs)
    }

    /// Process data received from TCP.
    ///
    /// During handshake, this decodes TLS records, decrypts encrypted records,
    /// routes handshake messages to the TLS handler, and manages key transitions.
    /// After handshake, this decrypts application data.
    ///
    /// Records are processed one at a time, interleaved with handler invocations,
    /// so that keys derived from processing one record are available to decrypt
    /// the next record.
    ///
    /// - Parameter data: Raw TCP data received
    /// - Returns: Output containing data to send, received application data, and status
    public func processReceivedData(_ data: Data) async throws -> TLSConnectionOutput {
        // Append to receive buffer
        connectionState.withLock { $0.receiveBuffer.append(data) }

        var dataToSend = Data()
        var applicationData = Data()
        var handshakeComplete = false
        var receivedAlert: TLSAlert?

        // Process records one at a time, interleaving with handler processing
        while true {
            // Extract one record atomically (decode + consume in single lock scope)
            let extracted = try connectionState.withLock { state -> TLSRecord? in
                guard let (record, consumed) = try TLSRecordCodec.decode(from: state.receiveBuffer) else {
                    return nil
                }
                state.receiveBuffer.removeFirst(consumed)
                return record
            }

            guard let record = extracted else { break }

            // Resolve: decrypt if this is an encrypted record
            let (contentType, payload) = try resolveRecord(record)

            switch contentType {
            case .handshake:
                let level = currentEncryptionLevel()
                let outputs = try await handler.processHandshakeData(payload, at: level)
                let encoded = try encodeOutputs(outputs, handshakeComplete: &handshakeComplete)
                dataToSend.append(encoded)

            case .applicationData:
                applicationData.append(payload)

            case .alert:
                let alert = try TLSAlert.decode(from: payload)
                receivedAlert = alert

            case .changeCipherSpec:
                continue // Ignore CCS in TLS 1.3 (middlebox compatibility)
            }
        }

        return TLSConnectionOutput(
            dataToSend: dataToSend,
            applicationData: applicationData,
            handshakeComplete: handshakeComplete,
            alert: receivedAlert
        )
    }

    /// Encrypt application data for sending over TCP.
    ///
    /// Fragments the data if it exceeds the maximum TLS plaintext size,
    /// encrypts each fragment with AEAD, and wraps in TLS record framing.
    ///
    /// - Parameter data: The plaintext application data
    /// - Returns: Encrypted TLS records ready to send over TCP
    /// - Throws: If the handshake is not complete or encryption fails
    public func writeApplicationData(_ data: Data) throws -> Data {
        let cryptor = connectionState.withLock { state -> TLSRecordCryptor? in
            guard state.handshakeCompleted else { return nil }
            return state.cryptor
        }

        guard let cryptor else {
            throw TLSConnectionError.handshakeNotComplete
        }

        return try encryptAndFrame(content: data, type: .applicationData, cryptor: cryptor)
    }

    /// Send a close_notify alert to gracefully terminate the connection.
    ///
    /// - Returns: The encoded close_notify TLS record to send over TCP
    public func close() throws -> Data {
        let cryptor = connectionState.withLock { state -> TLSRecordCryptor? in
            state.closed = true
            return state.cryptor
        }

        let alertData = TLSAlert.closeNotify.encode()
        if let cryptor {
            let ciphertext = try cryptor.encrypt(content: alertData, type: .alert)
            return TLSRecordCodec.encodeCiphertext(ciphertext)
        } else {
            return TLSRecordCodec.encodePlaintext(type: .alert, data: alertData)
        }
    }

    /// Whether the TLS handshake is complete and the connection is ready for application data
    public var isConnected: Bool {
        connectionState.withLock { $0.handshakeCompleted && !$0.closed }
    }

    /// The negotiated ALPN protocol (if any)
    public var negotiatedALPN: String? {
        handler.negotiatedALPN
    }

    /// Application-specific peer info returned by the certificate validator callback.
    ///
    /// For libp2p, this is typically the remote `PeerID` extracted from the
    /// peer's certificate extension during the handshake.
    public var validatedPeerInfo: (any Sendable)? {
        handler.validatedPeerInfo
    }

    /// The peer's certificate chain (DER encoded), leaf first.
    ///
    /// Available after the handshake completes and the peer has sent certificates.
    public var peerCertificates: [Data]? {
        handler.peerCertificates
    }

    // MARK: - Private State

    private struct ConnectionState: Sendable {
        var handshakeStarted: Bool = false
        var handshakeCompleted: Bool = false
        var closed: Bool = false
        var receiveBuffer: Data = Data()
        var cryptor: TLSRecordCryptor?
        var cipherSuite: CipherSuite?
        /// Deferred application receive keys (server-side only).
        /// The server emits keysAvailable(.application) during processClientHello,
        /// but still needs handshake receive keys to decrypt ClientFinished.
        /// These keys are applied when handshakeComplete fires.
        var pendingReceiveKeys: TrafficKeys?
    }

    // MARK: - Record Resolution

    /// Resolve a TLS record: decrypt if it is an encrypted record.
    ///
    /// In TLS 1.3, encrypted records use contentType .applicationData (0x17).
    /// After decryption, the inner plaintext reveals the actual content type.
    ///
    /// - Parameter record: The decoded TLS record
    /// - Returns: Tuple of (actual content type, payload data)
    private func resolveRecord(_ record: TLSRecord) throws -> (TLSContentType, Data) {
        if record.contentType == .applicationData {
            let cryptor = connectionState.withLock { $0.cryptor }
            if let cryptor {
                let (content, innerType) = try cryptor.decrypt(ciphertext: record.fragment)
                return (innerType, content)
            }
        }
        return (record.contentType, record.fragment)
    }

    /// Determine the current encryption level based on handshake state
    private func currentEncryptionLevel() -> TLSEncryptionLevel {
        let hasCryptor = connectionState.withLock { $0.cryptor != nil }
        return hasCryptor ? .handshake : .initial
    }

    // MARK: - Output Processing

    /// Encode TLS handler outputs into TCP-ready bytes.
    ///
    /// Handles the output ordering where handshake data at `.handshake` level
    /// may appear before the corresponding `.keysAvailable` output (this happens
    /// on the server side). Buffers such data and encrypts it when keys arrive.
    private func encodeOutputs(_ outputs: [TLSOutput]) throws -> Data {
        var dummy = false
        return try encodeOutputs(outputs, handshakeComplete: &dummy)
    }

    /// Encode TLS handler outputs into TCP-ready bytes.
    ///
    /// Processes outputs in order, handling the case where the server emits
    /// encrypted handshake data before the keysAvailable output:
    /// 1. `.handshakeData(data, .initial)` → plaintext record
    /// 2. `.handshakeData(data, .handshake)` → encrypt with current cryptor,
    ///    or buffer if cryptor not yet available
    /// 3. `.keysAvailable` → update cryptor, flush buffered data
    /// 4. `.handshakeComplete` → mark connection as established
    private func encodeOutputs(
        _ outputs: [TLSOutput],
        handshakeComplete: inout Bool
    ) throws -> Data {
        var dataToSend = Data()
        var pendingEncryptedData: [Data] = []

        for output in outputs {
            switch output {
            case .handshakeData(let data, let level):
                if level == .initial {
                    // Fragment plaintext if it exceeds max record size (RFC 8446 Section 5.1)
                    var offset = 0
                    while offset < data.count {
                        let end = min(offset + TLSRecordCodec.maxPlaintextSize, data.count)
                        let fragment = data[data.index(data.startIndex, offsetBy: offset)..<data.index(data.startIndex, offsetBy: end)]
                        dataToSend.append(TLSRecordCodec.encodePlaintext(type: .handshake, data: Data(fragment)))
                        offset = end
                    }
                } else {
                    let cryptor = connectionState.withLock { $0.cryptor }
                    if let cryptor {
                        let ciphertext = try cryptor.encrypt(content: data, type: .handshake)
                        dataToSend.append(TLSRecordCodec.encodeCiphertext(ciphertext))
                    } else {
                        // Keys not yet available (server-side: handshake data before keysAvailable)
                        pendingEncryptedData.append(data)
                    }
                }

            case .keysAvailable(let info):
                updateCryptor(with: info)

                // Flush any pending handshake data that was buffered before keys arrived
                if !pendingEncryptedData.isEmpty {
                    let cryptor = connectionState.withLock { $0.cryptor }
                    if let cryptor {
                        for pending in pendingEncryptedData {
                            let ciphertext = try cryptor.encrypt(content: pending, type: .handshake)
                            dataToSend.append(TLSRecordCodec.encodeCiphertext(ciphertext))
                        }
                    }
                    pendingEncryptedData.removeAll()
                }

            case .handshakeComplete:
                handshakeComplete = true
                connectionState.withLock { state in
                    state.handshakeCompleted = true
                    // Apply deferred application receive keys (server-side)
                    if let pendingKeys = state.pendingReceiveKeys {
                        state.cryptor?.updateReceiveKeys(pendingKeys)
                        state.pendingReceiveKeys = nil
                    }
                }

            case .alert(let alert):
                let cryptor = connectionState.withLock { $0.cryptor }
                let alertData = alert.encode()
                if let cryptor {
                    let ciphertext = try cryptor.encrypt(content: alertData, type: .alert)
                    dataToSend.append(TLSRecordCodec.encodeCiphertext(ciphertext))
                } else {
                    dataToSend.append(TLSRecordCodec.encodePlaintext(type: .alert, data: alertData))
                }

            case .newSessionTicket, .needMoreData, .error:
                break
            }
        }

        return dataToSend
    }

    // MARK: - Key Management

    /// Update the cryptor with new keys from the handler.
    ///
    /// Key transition timing in TLS 1.3:
    /// - **Handshake level**: Both send and receive keys are updated immediately.
    /// - **Application level on server**: Send keys update immediately (server needs to
    ///   send with application keys after handshake messages). Receive keys are DEFERRED
    ///   because the server emits `keysAvailable(.application)` during `processClientHello`,
    ///   but must still decrypt ClientFinished with handshake receive keys.
    ///   Deferred keys are applied when `handshakeComplete` fires.
    /// - **Application level on client**: Both keys update immediately. The client emits
    ///   `keysAvailable(.application)` after processing server Finished and sending
    ///   ClientFinished, so no handshake data remains.
    private func updateCryptor(with info: KeysAvailableInfo) {
        let receiveSecret = handler.isClient ? info.serverSecret : info.clientSecret
        let sendSecret = handler.isClient ? info.clientSecret : info.serverSecret

        if let recvSecret = receiveSecret, let sndSecret = sendSecret {
            let sendKeys = TrafficKeys(secret: sndSecret, cipherSuite: info.cipherSuite)

            connectionState.withLock { state in
                if state.cryptor == nil {
                    state.cryptor = TLSRecordCryptor(cipherSuite: info.cipherSuite)
                    state.cipherSuite = info.cipherSuite
                }
                state.cryptor?.updateSendKeys(sendKeys)

                if info.level == .application && !handler.isClient && !state.handshakeCompleted {
                    // Server initial handshake: defer receive key update until
                    // handshakeComplete fires (need handshake receive keys for ClientFinished).
                    // Post-handshake key updates (handshakeCompleted == true) apply immediately.
                    let receiveKeys = TrafficKeys(secret: recvSecret, cipherSuite: info.cipherSuite)
                    state.pendingReceiveKeys = receiveKeys
                } else {
                    let receiveKeys = TrafficKeys(secret: recvSecret, cipherSuite: info.cipherSuite)
                    state.cryptor?.updateReceiveKeys(receiveKeys)
                }
            }
        }
    }

    // MARK: - Encryption Helpers

    /// Encrypt content with AEAD and wrap in TLS record framing.
    /// Fragments if the content exceeds the maximum plaintext size.
    private func encryptAndFrame(
        content: Data,
        type: TLSContentType,
        cryptor: TLSRecordCryptor
    ) throws -> Data {
        var result = Data()
        var offset = 0

        while offset < content.count {
            let fragmentSize = min(TLSRecordCodec.maxPlaintextSize, content.count - offset)
            let start = content.index(content.startIndex, offsetBy: offset)
            let end = content.index(start, offsetBy: fragmentSize)
            let fragment = content[start..<end]

            let ciphertext = try cryptor.encrypt(content: Data(fragment), type: type)
            result.append(TLSRecordCodec.encodeCiphertext(ciphertext))

            offset += fragmentSize
        }

        return result
    }
}

// MARK: - TLS Connection Errors

/// Errors specific to TLSConnection
public enum TLSConnectionError: Error, Sendable {
    /// Attempted to send application data before handshake is complete
    case handshakeNotComplete
    /// Connection has been closed
    case connectionClosed
    /// Received fatal alert from peer
    case fatalAlert(TLSAlert)
}
