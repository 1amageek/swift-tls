/// TLS 1.3 Record Layer (RFC 8446 Section 5)
///
/// Combines framing (TLSRecordCodec) and encryption (TLSRecordCryptor)
/// with buffer management for processing TCP byte streams.

import Foundation
import Synchronization
import TLSCore

// MARK: - Record Layer Output

/// Output from processing received data through the record layer
public enum TLSRecordOutput: Sendable {
    /// Decrypted application data
    case applicationData(Data)
    /// Handshake message data
    case handshakeMessage(Data)
    /// Alert received
    case alert(TLSAlert)
    /// Change cipher spec (legacy, ignored in TLS 1.3)
    case changeCipherSpec
}

// MARK: - TLS Record Layer

/// Manages TLS record framing, encryption, and buffering for TCP streams.
///
/// This layer sits between the raw TCP transport and the TLS handshake/application layer.
/// It handles:
/// - Fragmenting outgoing data into TLS records
/// - Reassembling incoming TLS records from a TCP byte stream
/// - AEAD encryption/decryption after handshake keys are available
public final class TLSRecordLayer: Sendable {

    private let state: Mutex<RecordLayerState>

    /// The cipher suite used for encryption
    public let cipherSuite: CipherSuite

    /// The cryptor for AEAD operations
    private let cryptor: TLSRecordCryptor

    // MARK: - Initialization

    /// Creates a new record layer
    /// - Parameter cipherSuite: The negotiated cipher suite
    public init(cipherSuite: CipherSuite) {
        self.cipherSuite = cipherSuite
        self.cryptor = TLSRecordCryptor(cipherSuite: cipherSuite)
        self.state = Mutex(RecordLayerState())
    }

    // MARK: - Key Management

    /// Update both send and receive encryption keys.
    /// - Parameters:
    ///   - send: The send (write) traffic keys
    ///   - receive: The receive (read) traffic keys
    public func updateKeys(send: TrafficKeys, receive: TrafficKeys) {
        cryptor.updateSendKeys(send)
        cryptor.updateReceiveKeys(receive)
        state.withLock { state in
            state.sendEncryptionActive = true
            state.receiveEncryptionActive = true
        }
    }

    /// Update only the send (write) encryption keys.
    ///
    /// Use this when the send direction needs to transition to new keys
    /// independently of the receive direction. For example, a TLS 1.3 server
    /// activates handshake send keys before the client has sent its Finished.
    ///
    /// - Parameter keys: The send traffic keys
    public func updateSendKeys(_ keys: TrafficKeys) {
        cryptor.updateSendKeys(keys)
        state.withLock { $0.sendEncryptionActive = true }
    }

    /// Update only the receive (read) encryption keys.
    ///
    /// Use this when the receive direction needs to transition to new keys
    /// independently of the send direction. For example, a TLS 1.3 server
    /// defers application receive keys until ClientFinished is processed.
    ///
    /// - Parameter keys: The receive traffic keys
    public func updateReceiveKeys(_ keys: TrafficKeys) {
        cryptor.updateReceiveKeys(keys)
        state.withLock { $0.receiveEncryptionActive = true }
    }

    // MARK: - Writing

    /// Encrypt and frame application data as TLS records.
    ///
    /// Fragments the data if it exceeds the maximum plaintext size.
    ///
    /// - Parameter data: The application data to send
    /// - Returns: Encoded TLS ciphertext records ready to send over TCP
    public func writeApplicationData(_ data: Data) throws -> Data {
        try writeRecord(content: data, type: .applicationData)
    }

    /// Encode and optionally encrypt a handshake message.
    ///
    /// - Parameters:
    ///   - data: The handshake message data
    ///   - encrypted: Whether to encrypt the record
    /// - Returns: Encoded TLS record(s)
    public func writeHandshake(_ data: Data, encrypted: Bool) throws -> Data {
        if encrypted {
            return try writeRecord(content: data, type: .handshake)
        } else {
            return TLSRecordCodec.encodePlaintext(type: .handshake, data: data)
        }
    }

    /// Encode an alert as a TLS record.
    ///
    /// - Parameter alert: The alert to send
    /// - Returns: Encoded TLS record
    public func writeAlert(_ alert: TLSAlert) throws -> Data {
        let isEncrypted = state.withLock { $0.sendEncryptionActive }
        let alertData = alert.encode()
        if isEncrypted {
            return try writeRecord(content: alertData, type: .alert)
        } else {
            return TLSRecordCodec.encodePlaintext(type: .alert, data: alertData)
        }
    }

    /// Write a change_cipher_spec record (legacy compatibility)
    public func writeChangeCipherSpec() -> Data {
        TLSRecordCodec.encodePlaintext(type: .changeCipherSpec, data: Data([0x01]))
    }

    // MARK: - Reading

    /// Process received TCP data and extract TLS records.
    ///
    /// Buffers incomplete records and returns all complete records found.
    ///
    /// - Parameter data: Raw TCP data received
    /// - Returns: Array of decoded record layer outputs
    public func processReceivedData(_ data: Data) throws -> [TLSRecordOutput] {
        // Extract all complete records atomically in a single lock
        let records = try state.withLock { state -> [TLSRecord] in
            state.readBuffer.append(data)
            guard state.readBuffer.count <= RecordLayerState.maxBufferSize else {
                throw TLSRecordError.bufferOverflow
            }

            var extracted: [TLSRecord] = []
            while true {
                guard let (record, consumed) = try TLSRecordCodec.decode(from: state.readBuffer.unconsumed) else {
                    break
                }
                state.readBuffer.consumeFirst(consumed)
                extracted.append(record)
            }
            return extracted
        }

        // Process records outside the lock
        var outputs: [TLSRecordOutput] = []
        for record in records {
            let output = try processRecord(record)
            outputs.append(contentsOf: output)
        }
        return outputs
    }

    // MARK: - Private

    private struct RecordLayerState: Sendable {
        var readBuffer: OffsetBuffer = OffsetBuffer()
        var sendEncryptionActive: Bool = false
        var receiveEncryptionActive: Bool = false

        /// Maximum read buffer size (256KB) to prevent DoS via unbounded buffering
        static let maxBufferSize = 256 * 1024
    }

    /// Write encrypted record(s), fragmenting if necessary
    private func writeRecord(content: Data, type: TLSContentType) throws -> Data {
        var result = Data()
        var offset = 0

        while offset < content.count {
            let fragmentSize = min(TLSRecordCodec.maxPlaintextSize, content.count - offset)
            let fragment = content[content.index(content.startIndex, offsetBy: offset)..<content.index(content.startIndex, offsetBy: offset + fragmentSize)]

            let ciphertext = try cryptor.encrypt(content: Data(fragment), type: type)
            result.append(TLSRecordCodec.encodeCiphertext(ciphertext))

            offset += fragmentSize
        }

        return result
    }

    /// Process a single decoded record
    private func processRecord(_ record: TLSRecord) throws -> [TLSRecordOutput] {
        let isEncrypted = state.withLock { $0.receiveEncryptionActive }

        switch record.contentType {
        case .changeCipherSpec:
            // Ignore CCS in TLS 1.3 (middlebox compatibility)
            return [.changeCipherSpec]

        case .alert:
            let alertData: Data
            if isEncrypted {
                // Should not happen - encrypted alerts come as applicationData records
                let (decrypted, _) = try cryptor.decrypt(ciphertext: record.fragment)
                alertData = decrypted
            } else {
                alertData = record.fragment
            }
            let alert = try TLSAlert.decode(from: alertData)
            return [.alert(alert)]

        case .handshake:
            // Plaintext handshake (before encryption is active)
            return [.handshakeMessage(record.fragment)]

        case .applicationData:
            if isEncrypted {
                // Decrypt and extract inner content type
                let (content, innerType) = try cryptor.decrypt(ciphertext: record.fragment)

                switch innerType {
                case .applicationData:
                    return [.applicationData(content)]
                case .handshake:
                    return [.handshakeMessage(content)]
                case .alert:
                    let alert = try TLSAlert.decode(from: content)
                    return [.alert(alert)]
                case .changeCipherSpec:
                    return [.changeCipherSpec]
                }
            } else {
                // TLS 1.3: application data records before encryption is active
                // are a protocol violation (RFC 8446 Section 5)
                throw TLSRecordError.unexpectedPlaintextApplicationData
            }
        }
    }
}
