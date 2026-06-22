/// TLS 1.3 Early Data Extension (RFC 8446 Section 4.2.10)
///
/// The "early_data" extension indicates the client wishes to send 0-RTT data.
///
/// Context varies by message type:
/// - ClientHello: Empty (indicates client wants to send early data)
/// - EncryptedExtensions: Empty (server accepts early data)
/// - NewSessionTicket: Contains max_early_data_size
///
/// ```
/// struct {} Empty;
///
/// struct {
///     select (Handshake.msg_type) {
///         case new_session_ticket:   uint32 max_early_data_size;
///         case client_hello:         Empty;
///         case encrypted_extensions: Empty;
///     };
/// } EarlyDataIndication;
/// ```
///
/// The crypto-bearing `EarlyDataState` (which holds the client early traffic
/// secret) lives in the `TLSCore` adapter; this core file carries only the pure
/// wire types.

import P2PCoreBytes

// MARK: - Early Data Extension

/// Early data extension for 0-RTT
public enum EarlyDataExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .earlyData }

    /// ClientHello variant (empty - indicates desire to send early data)
    case clientHello

    /// EncryptedExtensions variant (empty - server accepts early data)
    case encryptedExtensions

    /// NewSessionTicket variant (contains max early data size)
    case newSessionTicket(maxEarlyDataSize: UInt32)

    // MARK: - Encoding

    public func encodeBytes() -> [UInt8] {
        switch self {
        case .clientHello, .encryptedExtensions:
            return []
        case .newSessionTicket(let maxSize):
            var writer = ByteWriter(reservingCapacity: 4)
            writer.writeUInt32(maxSize)
            return writer.finishArray()
        }
    }

    // MARK: - Decoding

    /// Decode ClientHello/EncryptedExtensions variant (empty)
    public static func decodeEmpty(from data: [UInt8]) throws(TLSWireError) -> EarlyDataExtension {
        guard data.isEmpty else {
            throw TLSWireError.decode(.invalidFormat("EarlyData: expected empty for ClientHello/EncryptedExtensions"))
        }
        return .clientHello // or .encryptedExtensions - same encoding
    }

    /// Decode NewSessionTicket variant
    public static func decodeNewSessionTicket(from data: [UInt8]) throws(TLSWireError) -> EarlyDataExtension {
        guard data.count == 4 else {
            throw TLSWireError.decode(.invalidFormat("EarlyData in NewSessionTicket: expected 4 bytes"))
        }

        var reader = ByteReader(data)
        let maxSize = try reader.wReadUInt32()
        return .newSessionTicket(maxEarlyDataSize: maxSize)
    }
}

// MARK: - End of Early Data Message

/// EndOfEarlyData message (RFC 8446 Section 4.5)
///
/// ```
/// struct {} EndOfEarlyData;
/// ```
///
/// Sent by the client after all 0-RTT application data to signal
/// the end of early data. This message is encrypted under the
/// handshake traffic key.
public struct EndOfEarlyData: Sendable {
    public init() {}

    public func encodeBytes() -> [UInt8] {
        []
    }

    public func encodeMessageBytes() -> [UInt8] {
        HandshakeCodec.encodeBytes(type: .endOfEarlyData, content: [])
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> EndOfEarlyData {
        guard data.isEmpty else {
            throw TLSWireError.decode(.invalidFormat("EndOfEarlyData must be empty"))
        }
        return EndOfEarlyData()
    }
}
