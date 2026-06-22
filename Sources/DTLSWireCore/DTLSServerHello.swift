/// DTLS 1.2 ServerHello (RFC 5246 Section 7.4.1.3)
///
/// struct {
///   ProtocolVersion server_version;
///   Random random;
///   SessionID session_id;
///   CipherSuite cipher_suite;
///   CompressionMethod compression_method;
///   Extension extensions<0..2^16-1>;
/// } ServerHello;

import P2PCoreBytes

/// DTLS 1.2 ServerHello message
public struct DTLSServerHello: Sendable {
    /// Server protocol version
    public let serverVersion: DTLSVersion

    /// 32-byte server random
    public let random: [UInt8]

    /// Session ID
    public let sessionID: [UInt8]

    /// Selected cipher suite
    public let cipherSuite: DTLSCipherSuite

    public init(
        serverVersion: DTLSVersion = .v1_2,
        random: [UInt8],
        sessionID: [UInt8] = [],
        cipherSuite: DTLSCipherSuite
    ) {
        self.serverVersion = serverVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
    }

    /// Encode the ServerHello body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()

        serverVersion.encode(writer: &writer)
        writer.writeBytes(random)
        try writer.dWriteVector8(sessionID)
        cipherSuite.encode(writer: &writer)
        writer.writeUInt8(0x00) // compression_method: null

        // ec_point_formats extension
        var extWriter = ByteWriter()
        extWriter.writeUInt16(0x000B) // ec_point_formats
        var ecWriter = ByteWriter()
        try ecWriter.dWriteVector8([0x00]) // uncompressed
        try extWriter.dWriteVector16(ecWriter.finishArray())

        try writer.dWriteVector16(extWriter.finishArray())

        return writer.finishArray()
    }

    /// Decode a ServerHello from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> DTLSServerHello {
        var reader = ByteReader(data)

        let version = try DTLSVersion.decode(reader: &reader)
        let random = try reader.dReadBytes(32)
        let sessionID = try reader.dReadVector8()
        let suite = try DTLSCipherSuite.decode(reader: &reader)
        _ = try reader.dReadUInt8() // compression_method

        // Skip extensions parsing for now
        return DTLSServerHello(
            serverVersion: version,
            random: random,
            sessionID: sessionID,
            cipherSuite: suite
        )
    }
}
