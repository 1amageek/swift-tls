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

import P2PCoreBytes

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
    public func encode(writer: inout ByteWriter) throws(DTLSWireError) {
        writer.writeUInt8(messageType.rawValue)
        try writer.dWriteUInt24(length)
        writer.writeUInt16(messageSeq)
        try writer.dWriteUInt24(fragmentOffset)
        try writer.dWriteUInt24(fragmentLength)
    }

    /// Decode header from wire format
    public static func decode(reader: inout ByteReader) throws(DTLSWireError) -> DTLSHandshakeHeader {
        let typeRaw = try reader.dReadUInt8()
        guard let messageType = DTLSHandshakeType(rawValue: typeRaw) else {
            throw DTLSWireError.dtls(.invalidFormat("Unknown handshake type: \(typeRaw)"))
        }
        let length = try reader.dReadUInt24()
        let messageSeq = try reader.dReadUInt16()
        let fragmentOffset = try reader.dReadUInt24()
        let fragmentLength = try reader.dReadUInt24()

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
        body: [UInt8]
    ) throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()
        let header = DTLSHandshakeHeader(
            messageType: type,
            length: UInt32(body.count),
            messageSeq: messageSeq
        )
        try header.encode(writer: &writer)
        writer.writeBytes(body)
        return writer.finishArray()
    }

    /// Fragment a handshake message into pieces that fit within maxFragmentSize.
    /// Each fragment includes the 12-byte header with proper fragmentOffset/fragmentLength.
    ///
    /// - Parameters:
    ///   - type: The handshake message type
    ///   - messageSeq: The message sequence number
    ///   - body: The complete message body
    ///   - maxFragmentSize: Maximum body size per fragment (default 1200 for UDP MTU safety)
    /// - Returns: Array of encoded fragments (each with header + body portion)
    public static func fragmentMessage(
        type: DTLSHandshakeType,
        messageSeq: UInt16,
        body: [UInt8],
        maxFragmentSize: Int = 1200
    ) throws(DTLSWireError) -> [[UInt8]] {
        let totalLength = UInt32(body.count)

        // If body fits in one fragment, return as single message
        if body.count <= maxFragmentSize {
            return [try encodeMessage(type: type, messageSeq: messageSeq, body: body)]
        }

        var fragments: [[UInt8]] = []
        var offset = 0

        while offset < body.count {
            let remainingLength = body.count - offset
            let fragmentLength = min(remainingLength, maxFragmentSize)

            let fragmentBody = Array(body[offset..<(offset + fragmentLength)])

            var writer = ByteWriter()
            let header = DTLSHandshakeHeader(
                messageType: type,
                length: totalLength,
                messageSeq: messageSeq,
                fragmentOffset: UInt32(offset),
                fragmentLength: UInt32(fragmentLength)
            )
            try header.encode(writer: &writer)
            writer.writeBytes(fragmentBody)
            fragments.append(writer.finishArray())

            offset += fragmentLength
        }

        return fragments
    }
}
