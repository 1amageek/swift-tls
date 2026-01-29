/// DTLS 1.2 ClientHello (RFC 6347 Section 4.2.1)
///
/// Same as TLS 1.2 ClientHello but with an additional cookie field for
/// DoS protection via HelloVerifyRequest exchange.
///
/// struct {
///   ProtocolVersion client_version;
///   Random random;
///   SessionID session_id;
///   opaque cookie<0..2^8-1>;           // DTLS-specific
///   CipherSuite cipher_suites<2..2^16-2>;
///   CompressionMethod compression_methods<1..2^8-1>;
///   Extension extensions<0..2^16-1>;   // optional
/// } ClientHello;

import Foundation
import Crypto
import TLSCore

/// DTLS 1.2 ClientHello message
public struct DTLSClientHello: Sendable {
    /// Client protocol version (DTLS 1.2 = 0xFEFD)
    public let clientVersion: DTLSVersion

    /// 32-byte client random
    public let random: Data

    /// Session ID (0-32 bytes, typically empty for new connections)
    public let sessionID: Data

    /// Cookie for DoS protection (from HelloVerifyRequest)
    public let cookie: Data

    /// Offered cipher suites
    public let cipherSuites: [DTLSCipherSuite]

    /// Supported elliptic curves (as extension data)
    public let supportedGroups: [TLSCore.NamedGroup]

    /// Supported signature algorithms
    public let signatureAlgorithms: [TLSCore.SignatureScheme]

    public init(
        clientVersion: DTLSVersion = .v1_2,
        random: Data? = nil,
        sessionID: Data = Data(),
        cookie: Data = Data(),
        cipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        supportedGroups: [TLSCore.NamedGroup] = [.secp256r1],
        signatureAlgorithms: [TLSCore.SignatureScheme] = [.ecdsa_secp256r1_sha256]
    ) {
        self.clientVersion = clientVersion
        self.random = random ?? (try! secureRandomBytes(count: 32))
        self.sessionID = sessionID
        self.cookie = cookie
        self.cipherSuites = cipherSuites
        self.supportedGroups = supportedGroups
        self.signatureAlgorithms = signatureAlgorithms
    }

    /// Encode the ClientHello body (without handshake header)
    public func encode() -> Data {
        var writer = TLSWriter()

        // client_version
        clientVersion.encode(writer: &writer)

        // random (32 bytes)
        writer.writeBytes(random)

        // session_id
        writer.writeVector8(sessionID)

        // cookie (DTLS-specific)
        writer.writeVector8(cookie)

        // cipher_suites
        var suitesWriter = TLSWriter()
        for suite in cipherSuites {
            suite.encode(writer: &suitesWriter)
        }
        writer.writeVector16(suitesWriter.finish())

        // compression_methods (only null compression)
        writer.writeVector8(Data([0x00]))

        // extensions
        var extWriter = TLSWriter()
        encodeExtensions(writer: &extWriter)
        let extData = extWriter.finish()
        if !extData.isEmpty {
            writer.writeVector16(extData)
        }

        return writer.finish()
    }

    private func encodeExtensions(writer: inout TLSWriter) {
        // supported_groups extension (0x000A)
        if !supportedGroups.isEmpty {
            writer.writeUInt16(0x000A) // extension type
            var groupWriter = TLSWriter()
            var groupList = TLSWriter()
            for group in supportedGroups {
                groupList.writeUInt16(group.rawValue)
            }
            groupWriter.writeVector16(groupList.finish())
            writer.writeVector16(groupWriter.finish())
        }

        // signature_algorithms extension (0x000D)
        if !signatureAlgorithms.isEmpty {
            writer.writeUInt16(0x000D) // extension type
            var sigWriter = TLSWriter()
            var sigList = TLSWriter()
            for scheme in signatureAlgorithms {
                sigList.writeUInt16(scheme.rawValue)
            }
            sigWriter.writeVector16(sigList.finish())
            writer.writeVector16(sigWriter.finish())
        }

        // ec_point_formats extension (0x000B) — uncompressed only
        writer.writeUInt16(0x000B)
        var ecWriter = TLSWriter()
        ecWriter.writeVector8(Data([0x00])) // uncompressed
        writer.writeVector16(ecWriter.finish())
    }

    /// Decode a ClientHello from body data
    public static func decode(from data: Data) throws -> DTLSClientHello {
        var reader = TLSReader(data: data)

        let version = try DTLSVersion.decode(reader: &reader)
        let random = try reader.readBytes(32)
        let sessionID = try reader.readVector8()
        let cookie = try reader.readVector8()

        // cipher_suites
        let suitesData = try reader.readVector16()
        var suitesReader = TLSReader(data: suitesData)
        var suites: [DTLSCipherSuite] = []
        while suitesReader.hasMore {
            let value = try suitesReader.readUInt16()
            if let suite = DTLSCipherSuite(rawValue: value) {
                suites.append(suite)
            }
        }

        // compression_methods (skip)
        _ = try reader.readVector8()

        // Parse extensions if present
        var groups: [TLSCore.NamedGroup] = []
        var sigAlgs: [TLSCore.SignatureScheme] = []

        if reader.hasMore {
            let extData = try reader.readVector16()
            var extReader = TLSReader(data: extData)
            while extReader.hasMore {
                let extType = try extReader.readUInt16()
                let extBody = try extReader.readVector16()

                switch extType {
                case 0x000A: // supported_groups
                    var groupReader = TLSReader(data: extBody)
                    let groupList = try groupReader.readVector16()
                    var groupListReader = TLSReader(data: groupList)
                    while groupListReader.hasMore {
                        let value = try groupListReader.readUInt16()
                        if let group = TLSCore.NamedGroup(rawValue: value) {
                            groups.append(group)
                        }
                    }
                case 0x000D: // signature_algorithms
                    var sigReader = TLSReader(data: extBody)
                    let sigList = try sigReader.readVector16()
                    var sigListReader = TLSReader(data: sigList)
                    while sigListReader.hasMore {
                        let value = try sigListReader.readUInt16()
                        if let scheme = TLSCore.SignatureScheme(rawValue: value) {
                            sigAlgs.append(scheme)
                        }
                    }
                default:
                    break // skip unknown extensions
                }
            }
        }

        return DTLSClientHello(
            clientVersion: version,
            random: random,
            sessionID: sessionID,
            cookie: cookie,
            cipherSuites: suites,
            supportedGroups: groups,
            signatureAlgorithms: sigAlgs
        )
    }
}
