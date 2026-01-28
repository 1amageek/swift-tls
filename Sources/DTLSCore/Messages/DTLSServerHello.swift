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

import Foundation
import TLSCore

/// DTLS 1.2 ServerHello message
public struct DTLSServerHello: Sendable {
    /// Server protocol version
    public let serverVersion: DTLSVersion

    /// 32-byte server random
    public let random: Data

    /// Session ID
    public let sessionID: Data

    /// Selected cipher suite
    public let cipherSuite: DTLSCipherSuite

    public init(
        serverVersion: DTLSVersion = .v1_2,
        random: Data? = nil,
        sessionID: Data = Data(),
        cipherSuite: DTLSCipherSuite
    ) {
        self.serverVersion = serverVersion
        self.random = random ?? Self.generateRandom()
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
    }

    private static func generateRandom() -> Data {
        var bytes = Data(count: 32)
        bytes.withUnsafeMutableBytes { ptr in
            let _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        return bytes
    }

    /// Encode the ServerHello body
    public func encode() -> Data {
        var writer = TLSWriter()

        serverVersion.encode(writer: &writer)
        writer.writeBytes(random)
        writer.writeVector8(sessionID)
        cipherSuite.encode(writer: &writer)
        writer.writeUInt8(0x00) // compression_method: null

        // ec_point_formats extension
        var extWriter = TLSWriter()
        extWriter.writeUInt16(0x000B) // ec_point_formats
        var ecWriter = TLSWriter()
        ecWriter.writeVector8(Data([0x00])) // uncompressed
        extWriter.writeVector16(ecWriter.finish())

        writer.writeVector16(extWriter.finish())

        return writer.finish()
    }

    /// Decode a ServerHello from body data
    public static func decode(from data: Data) throws -> DTLSServerHello {
        var reader = TLSReader(data: data)

        let version = try DTLSVersion.decode(reader: &reader)
        let random = try reader.readBytes(32)
        let sessionID = try reader.readVector8()
        let suite = try DTLSCipherSuite.decode(reader: &reader)
        _ = try reader.readUInt8() // compression_method

        // Skip extensions parsing for now
        return DTLSServerHello(
            serverVersion: version,
            random: random,
            sessionID: sessionID,
            cipherSuite: suite
        )
    }
}
