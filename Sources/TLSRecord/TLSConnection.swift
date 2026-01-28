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

    /// Session tickets received from the server (post-handshake)
    public let sessionTickets: [NewSessionTicketInfo]

    public init(
        dataToSend: Data = Data(),
        applicationData: Data = Data(),
        handshakeComplete: Bool = false,
        alert: TLSAlert? = nil,
        sessionTickets: [NewSessionTicketInfo] = []
    ) {
        self.dataToSend = dataToSend
        self.applicationData = applicationData
        self.handshakeComplete = handshakeComplete
        self.alert = alert
        self.sessionTickets = sessionTickets
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
///
/// ## Concurrency Model
///
/// Uses a 3-lock architecture for safe concurrent access:
/// - `sharedState`: flags, cryptor reference, error state (short hold)
/// - `writeLock`: serializes all send operations (nonce + wire order)
/// - `readLock`: serializes all receive operations + buffer management
///
/// Lock ordering (deadlock prevention): readLock → writeLock → sharedState
public final class TLSConnection: Sendable {

    private let handler: TLS13Handler
    private let sharedState: Mutex<SharedState>
    private let writeLock: Mutex<WriteState>
    private let readLock: Mutex<ReadState>

    // MARK: - Initialization

    /// Creates a new TLS connection
    /// - Parameter configuration: The TLS configuration
    public init(configuration: TLSConfiguration = TLSConfiguration()) {
        self.handler = TLS13Handler(configuration: configuration)
        self.sharedState = Mutex(SharedState())
        self.writeLock = Mutex(WriteState())
        self.readLock = Mutex(ReadState())
    }

    // MARK: - Public API

    /// Start the TLS handshake.
    ///
    /// - Parameter isClient: true for client mode, false for server mode
    /// - Returns: Data to send over TCP (ClientHello for clients, empty for servers)
    public func startHandshake(isClient: Bool) async throws -> Data {
        try checkFatalError()
        let outputs = try await handler.startHandshake(isClient: isClient)

        sharedState.withLock { state in
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
    /// - Throws: `TLSConnectionError.concurrentReadNotAllowed` if called concurrently,
    ///           `TLSConnectionError.fatalProtocolError` if a prior fatal error occurred
    public func processReceivedData(_ data: Data) async throws -> TLSConnectionOutput {
        // Check for fatal error before proceeding
        try checkFatalError()

        // Acquire readLock: check for concurrent reads and buffer data
        try readLock.withLock { readState in
            guard !readState.isProcessing else {
                throw TLSConnectionError.concurrentReadNotAllowed
            }
            readState.isProcessing = true
            readState.receiveBuffer.append(data)
            guard readState.receiveBuffer.count <= ReadState.maxReceiveBufferSize else {
                readState.isProcessing = false
                throw TLSConnectionError.bufferOverflow
            }
        }

        // Ensure isProcessing is cleared on exit
        defer {
            readLock.withLock { $0.isProcessing = false }
        }

        do {
            return try await processReceivedDataInner()
        } catch {
            // Classify error: set fatal state for protocol-level errors
            if let kind = classifyFatalError(error) {
                sharedState.withLock { state in
                    if state.fatalError == nil {
                        state.fatalError = .fatalProtocolError(kind)
                    }
                }
            }
            throw error
        }
    }

    /// Encrypt application data for sending over TCP.
    ///
    /// Fragments the data if it exceeds the maximum TLS plaintext size,
    /// encrypts each fragment with AEAD, and wraps in TLS record framing.
    ///
    /// - Parameter data: The plaintext application data
    /// - Returns: Encrypted TLS records ready to send over TCP
    /// - Throws: If the handshake is not complete, connection is closed,
    ///           a fatal error occurred, or encryption fails
    public func writeApplicationData(_ data: Data) throws -> Data {
        try writeLock.withLock { _ -> Data in
            // Check shared state under writeLock for atomic close/error check + encrypt
            let cryptor = try sharedState.withLock { state -> TLSRecordCryptor in
                if let fatalErr = state.fatalError {
                    throw fatalErr
                }
                guard !state.closed else {
                    throw TLSConnectionError.connectionClosed
                }
                guard state.handshakeCompleted, let cryptor = state.cryptor else {
                    throw TLSConnectionError.handshakeNotComplete
                }
                return cryptor
            }

            return try encryptAndFrame(content: data, type: .applicationData, cryptor: cryptor)
        }
    }

    /// Send a close_notify alert to gracefully terminate the connection.
    ///
    /// - Returns: The encoded close_notify TLS record to send over TCP
    public func close() throws -> Data {
        try writeLock.withLock { _ -> Data in
            let cryptor = try sharedState.withLock { state -> TLSRecordCryptor? in
                if let err = state.fatalError {
                    throw err
                }
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
    }

    /// Whether the TLS handshake is complete and the connection is ready for application data
    public var isConnected: Bool {
        sharedState.withLock { $0.handshakeCompleted && !$0.closed && $0.fatalError == nil }
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

    private struct SharedState: Sendable {
        var handshakeStarted: Bool = false
        var handshakeCompleted: Bool = false
        var closed: Bool = false
        var fatalError: TLSConnectionError? = nil
        var cryptor: TLSRecordCryptor? = nil
        var cipherSuite: CipherSuite? = nil
        /// Deferred application receive keys (server-side only).
        /// The server emits keysAvailable(.application) during processClientHello,
        /// but still needs handshake receive keys to decrypt ClientFinished.
        /// These keys are applied when handshakeComplete fires.
        var pendingReceiveKeys: TrafficKeys? = nil
        /// Separate cryptor for 0-RTT early data (RFC 8446 Section 2.3).
        ///
        /// During 0-RTT, early data keys are installed on this cryptor
        /// instead of overwriting the main cryptor's handshake keys.
        /// - Client: holds early data send keys (for encrypting EndOfEarlyData)
        /// - Server: holds early data receive keys (for decrypting 0-RTT records)
        ///
        /// Cleared when `.earlyDataEnd` is processed (after EndOfEarlyData
        /// or when 0-RTT is rejected).
        var earlyDataCryptor: TLSRecordCryptor? = nil
    }

    private struct WriteState: Sendable {
        var placeholder: Bool = false  // Mutex itself provides serialization
    }

    private struct ReadState: Sendable {
        var receiveBuffer: OffsetBuffer = OffsetBuffer()
        var isProcessing: Bool = false

        /// Maximum receive buffer size (256KB) to prevent DoS via unbounded buffering
        static let maxReceiveBufferSize = 256 * 1024
    }

    // MARK: - Fatal Error Check

    /// Check for fatal error state and throw if present.
    private func checkFatalError() throws {
        if let err = sharedState.withLock({ $0.fatalError }) {
            throw err
        }
    }

    /// Classify an error into a fatal protocol error kind, or return nil if non-fatal.
    ///
    /// This replaces the former `isFatalError()` check and wrapping logic,
    /// unifying classification and value construction in one function.
    private func classifyFatalError(_ error: Error) -> FatalProtocolErrorKind? {
        switch error {
        case let e as TLSRecordError:
            return .record(e)
        case let e as TLSHandshakeError:
            return .handshake(e)
        case let e as TLSError:
            return .other(String(describing: e))
        case let e as TLSConnectionError:
            switch e {
            case .fatalAlert, .fatalProtocolError:
                return .other(String(describing: e))
            case .handshakeNotComplete, .connectionClosed, .bufferOverflow, .concurrentReadNotAllowed:
                return nil
            }
        default:
            return nil
        }
    }

    // MARK: - Inner Processing

    /// Process received data after readLock has been acquired and buffer populated.
    private func processReceivedDataInner() async throws -> TLSConnectionOutput {
        var dataToSend = Data()
        var applicationData = Data()
        var handshakeComplete = false
        var receivedAlert: TLSAlert?
        var sessionTickets: [NewSessionTicketInfo] = []

        // Process records one at a time, interleaving with handler processing
        while true {
            // Extract one record atomically from readLock
            let extracted = try readLock.withLock { readState -> TLSRecord? in
                guard let (record, consumed) = try TLSRecordCodec.decode(from: readState.receiveBuffer.unconsumed) else {
                    return nil
                }
                readState.receiveBuffer.consumeFirst(consumed)
                return record
            }

            guard let record = extracted else { break }

            // Resolve: decrypt if this is an encrypted record
            let (contentType, payload) = try resolveRecord(record)

            switch contentType {
            case .handshake:
                let level = currentEncryptionLevel()
                let outputs = try await handler.processHandshakeData(payload, at: level)
                let encoded = try encodeOutputs(outputs, handshakeComplete: &handshakeComplete, sessionTickets: &sessionTickets)
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
            alert: receivedAlert,
            sessionTickets: sessionTickets
        )
    }

    // MARK: - Record Resolution

    /// Resolve a TLS record: decrypt if it is an encrypted record.
    ///
    /// In TLS 1.3, encrypted records use contentType .applicationData (0x17).
    /// After decryption, the inner plaintext reveals the actual content type.
    ///
    /// During the 0-RTT phase (earlyDataCryptor is set), incoming encrypted records
    /// are decrypted with the earlyDataCryptor. After EndOfEarlyData is processed
    /// and earlyDataCryptor is cleared, the main cryptor handles decryption.
    ///
    /// - Parameter record: The decoded TLS record
    /// - Returns: Tuple of (actual content type, payload data)
    private func resolveRecord(_ record: TLSRecord) throws -> (TLSContentType, Data) {
        if record.contentType == .applicationData {
            let (earlyDataCryptor, mainCryptor) = sharedState.withLock {
                ($0.earlyDataCryptor, $0.cryptor)
            }

            // During 0-RTT phase, use earlyDataCryptor for all incoming records
            if let earlyDataCryptor {
                let (content, innerType) = try earlyDataCryptor.decrypt(ciphertext: record.fragment)
                return (innerType, content)
            }

            guard let mainCryptor else {
                // RFC 8446 Section 5: applicationData records before encryption
                // is active are a protocol violation.
                throw TLSRecordError.unexpectedPlaintextApplicationData
            }
            let (content, innerType) = try mainCryptor.decrypt(ciphertext: record.fragment)
            return (innerType, content)
        }

        // changeCipherSpec is always unencrypted (middlebox compatibility)
        if record.contentType == .changeCipherSpec {
            return (.changeCipherSpec, record.fragment)
        }

        // RFC 8446 Section 5: After encryption is active, handshake and alert
        // records MUST arrive inside encrypted applicationData records.
        let hasCryptor = sharedState.withLock { $0.cryptor != nil }
        if hasCryptor {
            switch record.contentType {
            case .handshake:
                throw TLSRecordError.unexpectedPlaintextHandshake
            case .alert:
                throw TLSRecordError.unexpectedPlaintextAlert
            default:
                break
            }
        }

        return (record.contentType, record.fragment)
    }

    /// Determine the current encryption level based on handshake state.
    ///
    /// During the 0-RTT phase (earlyDataCryptor is set), incoming records
    /// are at `.earlyData` level. After EndOfEarlyData clears earlyDataCryptor,
    /// the level returns to `.handshake`.
    ///
    /// After the handshake completes, post-handshake messages (KeyUpdate,
    /// NewSessionTicket) are processed at `.application` level, not `.handshake`.
    private func currentEncryptionLevel() -> TLSEncryptionLevel {
        let (completed, hasCryptor, hasEarlyDataCryptor) = sharedState.withLock {
            ($0.handshakeCompleted, $0.cryptor != nil, $0.earlyDataCryptor != nil)
        }
        if completed { return .application }
        if hasEarlyDataCryptor { return .earlyData }
        if hasCryptor { return .handshake }
        return .initial
    }

    // MARK: - Output Processing

    /// Encode TLS handler outputs into TCP-ready bytes.
    ///
    /// Handles the output ordering where handshake data at `.handshake` level
    /// may appear before the corresponding `.keysAvailable` output (this happens
    /// on the server side). Buffers such data and encrypts it when keys arrive.
    private func encodeOutputs(_ outputs: [TLSOutput]) throws -> Data {
        var dummy = false
        var tickets: [NewSessionTicketInfo] = []
        return try encodeOutputs(outputs, handshakeComplete: &dummy, sessionTickets: &tickets)
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
        handshakeComplete: inout Bool,
        sessionTickets: inout [NewSessionTicketInfo]
    ) throws -> Data {
        // Handshake response encryption is serialized via writeLock
        // to prevent nonce/wire order mismatches with concurrent writeApplicationData
        return try writeLock.withLock { _ -> Data in
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
                    } else if level == .earlyData {
                        // 0-RTT: encrypt with earlyDataCryptor (e.g., client sending EndOfEarlyData)
                        let earlyDataCryptor = sharedState.withLock { $0.earlyDataCryptor }
                        if let earlyDataCryptor {
                            dataToSend.append(try encryptAndFrame(content: data, type: .handshake, cryptor: earlyDataCryptor))
                        } else {
                            // earlyDataCryptor should be available; fall back to main cryptor
                            let cryptor = sharedState.withLock { $0.cryptor }
                            if let cryptor {
                                dataToSend.append(try encryptAndFrame(content: data, type: .handshake, cryptor: cryptor))
                            } else {
                                pendingEncryptedData.append(data)
                            }
                        }
                    } else {
                        let cryptor = sharedState.withLock { $0.cryptor }
                        if let cryptor {
                            // Fragment before encryption (RFC 8446 Section 5.1: 16KB max plaintext)
                            dataToSend.append(try encryptAndFrame(content: data, type: .handshake, cryptor: cryptor))
                        } else {
                            // Keys not yet available (server-side: handshake data before keysAvailable)
                            pendingEncryptedData.append(data)
                        }
                    }

                case .keysAvailable(let info):
                    updateCryptor(with: info)

                    // Flush any pending handshake data that was buffered before keys arrived
                    if !pendingEncryptedData.isEmpty {
                        let cryptor = sharedState.withLock { $0.cryptor }
                        if let cryptor {
                            for pending in pendingEncryptedData {
                                // Fragment before encryption (RFC 8446 Section 5.1: 16KB max plaintext)
                                dataToSend.append(try encryptAndFrame(content: pending, type: .handshake, cryptor: cryptor))
                            }
                        }
                        pendingEncryptedData.removeAll()
                    }

                case .earlyDataEnd:
                    // Clear the early data cryptor — subsequent records use the main cryptor
                    sharedState.withLock { $0.earlyDataCryptor = nil }

                case .handshakeComplete:
                    handshakeComplete = true
                    sharedState.withLock { state in
                        state.handshakeCompleted = true
                        // Apply deferred application receive keys (server-side)
                        if let pendingKeys = state.pendingReceiveKeys {
                            state.cryptor?.updateReceiveKeys(pendingKeys)
                            state.pendingReceiveKeys = nil
                        }
                    }

                case .alert(let alert):
                    let cryptor = sharedState.withLock { $0.cryptor }
                    let alertData = alert.encode()
                    if let cryptor {
                        let ciphertext = try cryptor.encrypt(content: alertData, type: .alert)
                        dataToSend.append(TLSRecordCodec.encodeCiphertext(ciphertext))
                    } else {
                        dataToSend.append(TLSRecordCodec.encodePlaintext(type: .alert, data: alertData))
                    }

                case .newSessionTicket(let info):
                    sessionTickets.append(info)

                case .needMoreData:
                    break
                }
            }

            return dataToSend
        }
    }

    // MARK: - Key Management

    /// Update the cryptor with new keys from the handler.
    ///
    /// Key transition timing in TLS 1.3:
    /// - **Early data level**: Keys are installed on a **separate** `earlyDataCryptor`
    ///   to avoid overwriting handshake keys on the main cryptor.
    ///   Client gets send-only keys (for 0-RTT data + EndOfEarlyData).
    ///   Server gets receive-only keys (for decrypting 0-RTT records).
    /// - **Handshake level**: Both send and receive keys are updated immediately
    ///   on the main cryptor.
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

        // Early data keys go to a separate cryptor to preserve handshake keys
        if info.level == .earlyData {
            sharedState.withLock { state in
                let earlyDataCryptor = TLSRecordCryptor(cipherSuite: info.cipherSuite)
                if let sndSecret = sendSecret {
                    let sendKeys = TrafficKeys(secret: sndSecret, cipherSuite: info.cipherSuite)
                    earlyDataCryptor.updateSendKeys(sendKeys)
                }
                if let recvSecret = receiveSecret {
                    let receiveKeys = TrafficKeys(secret: recvSecret, cipherSuite: info.cipherSuite)
                    earlyDataCryptor.updateReceiveKeys(receiveKeys)
                }
                state.earlyDataCryptor = earlyDataCryptor
            }
            return
        }

        sharedState.withLock { state in
            // Ensure cryptor exists
            if state.cryptor == nil {
                state.cryptor = TLSRecordCryptor(cipherSuite: info.cipherSuite)
                state.cipherSuite = info.cipherSuite
            }

            // Update send keys if available
            if let sndSecret = sendSecret {
                let sendKeys = TrafficKeys(secret: sndSecret, cipherSuite: info.cipherSuite)
                state.cryptor?.updateSendKeys(sendKeys)
            }

            // Update receive keys if available
            if let recvSecret = receiveSecret {
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
        // Pre-allocate result capacity: each fragment produces a TLS record
        // (5-byte header + fragment + content-type byte + 16-byte AEAD tag)
        let fragmentCount = (content.count + TLSRecordCodec.maxPlaintextSize - 1) / max(TLSRecordCodec.maxPlaintextSize, 1)
        let overhead = TLSRecordCodec.headerSize + 1 + 16 // header + content type + AEAD tag
        var result = Data()
        result.reserveCapacity(content.count + fragmentCount * overhead)

        var offset = 0
        while offset < content.count {
            let fragmentSize = min(TLSRecordCodec.maxPlaintextSize, content.count - offset)
            let start = content.index(content.startIndex, offsetBy: offset)
            let end = content.index(start, offsetBy: fragmentSize)
            // Data(fragment) creates a contiguous copy required by AEAD encryption
            let fragment = Data(content[start..<end])

            let ciphertext = try cryptor.encrypt(content: fragment, type: type)
            result.append(TLSRecordCodec.encodeCiphertext(ciphertext))

            offset += fragmentSize
        }

        return result
    }
}

// MARK: - TLS Connection Errors

/// Describes the kind of fatal protocol error that occurred.
///
/// This is a Sendable descriptor, not an Error itself.
/// Callers should catch ``TLSConnectionError/fatalProtocolError(_:)``.
public enum FatalProtocolErrorKind: Sendable, CustomStringConvertible {
    /// A TLS record-layer error (framing, decryption, MAC failure)
    case record(TLSRecordError)
    /// A TLS handshake-layer error (negotiation, verification, state machine)
    case handshake(TLSHandshakeError)
    /// An unclassified fatal error
    case other(String)

    public var description: String {
        switch self {
        case .record(let e):    return "record: \(e)"
        case .handshake(let e): return "handshake: \(e)"
        case .other(let msg):   return msg
        }
    }
}

/// Errors specific to TLSConnection
public enum TLSConnectionError: Error, Sendable {
    /// Attempted to send application data before handshake is complete
    case handshakeNotComplete
    /// Connection has been closed
    case connectionClosed
    /// Received fatal alert from peer
    case fatalAlert(TLSAlert)
    /// Receive buffer exceeded maximum size
    case bufferOverflow
    /// Concurrent read operations are not allowed
    case concurrentReadNotAllowed
    /// A fatal protocol error occurred; connection is permanently failed
    case fatalProtocolError(FatalProtocolErrorKind)
}
