/// DTLS 1.2 Handshake Header (RFC 6347 Section 4.2.2)
///
/// 12-byte header for DTLS handshake messages:
///   msg_type:        1 byte
///   length:          3 bytes (total message length)
///   message_seq:     2 bytes (DTLS-specific sequence number)
///   fragment_offset: 3 bytes (DTLS-specific)
///   fragment_length: 3 bytes (DTLS-specific)
///
/// TLS 1.3 uses only 4 bytes (type + length). DTLS adds 8 bytes for
/// message sequencing and fragmentation support.

import Foundation
import TLSCore

/// DTLS handshake message header
public struct DTLSHandshakeHeader: Sendable, Equatable {
    /// Handshake message type
    public var messageType: DTLSHandshakeType

    /// Total message body length (excluding header)
    public var length: UInt32

    /// Message sequence number (DTLS-specific, increments per handshake message)
    public var messageSeq: UInt16

    /// Fragment offset within the message body
    public var fragmentOffset: UInt32

    /// Fragment length (equals length when not fragmented)
    public var fragmentLength: UInt32

    /// Header size in bytes
    public static let headerSize = 12

    public init(
        messageType: DTLSHandshakeType,
        length: UInt32,
        messageSeq: UInt16,
        fragmentOffset: UInt32 = 0,
        fragmentLength: UInt32? = nil
    ) {
        self.messageType = messageType
        self.length = length
        self.messageSeq = messageSeq
        self.fragmentOffset = fragmentOffset
        self.fragmentLength = fragmentLength ?? length
    }

    /// Whether this message is fragmented
    public var isFragmented: Bool {
        fragmentOffset != 0 || fragmentLength != length
    }

    /// Encode header to wire format
    public func encode(writer: inout TLSWriter) {
        writer.writeUInt8(messageType.rawValue)
        writer.writeUInt24(length)
        writer.writeUInt16(messageSeq)
        writer.writeUInt24(fragmentOffset)
        writer.writeUInt24(fragmentLength)
    }

    /// Decode header from wire format
    public static func decode(reader: inout TLSReader) throws -> DTLSHandshakeHeader {
        let typeRaw = try reader.readUInt8()
        guard let messageType = DTLSHandshakeType(rawValue: typeRaw) else {
            throw DTLSError.invalidFormat("Unknown handshake type: \(typeRaw)")
        }
        let length = try reader.readUInt24()
        let messageSeq = try reader.readUInt16()
        let fragmentOffset = try reader.readUInt24()
        let fragmentLength = try reader.readUInt24()

        return DTLSHandshakeHeader(
            messageType: messageType,
            length: length,
            messageSeq: messageSeq,
            fragmentOffset: fragmentOffset,
            fragmentLength: fragmentLength
        )
    }

    /// Encode a complete handshake message (header + body)
    public static func encodeMessage(
        type: DTLSHandshakeType,
        messageSeq: UInt16,
        body: Data
    ) -> Data {
        var writer = TLSWriter()
        let header = DTLSHandshakeHeader(
            messageType: type,
            length: UInt32(body.count),
            messageSeq: messageSeq
        )
        header.encode(writer: &writer)
        writer.writeBytes(body)
        return writer.finish()
    }
}
