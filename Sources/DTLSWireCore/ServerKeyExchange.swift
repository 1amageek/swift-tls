/// DTLS 1.2 ServerKeyExchange (RFC 5246 Section 7.4.3)
///
/// For ECDHE key exchange:
/// struct {
///   ECParameters curve_params;
///   ECPoint public;
///   digitally-signed struct {
///     opaque client_random[32];
///     opaque server_random[32];
///     ServerECDHParams params;
///   } signed_params;
/// } ServerKeyExchange;

import P2PCoreBytes
import TLSWireCore

/// DTLS 1.2 ServerKeyExchange message for ECDHE
public struct ServerKeyExchange: Sendable {
    /// Named curve used
    public let namedGroup: NamedGroup

    /// Server's ephemeral ECDH public key
    public let publicKey: [UInt8]

    /// Signature algorithm
    public let signatureScheme: SignatureScheme

    /// Signature over the params
    public let signature: [UInt8]

    public init(
        namedGroup: NamedGroup,
        publicKey: [UInt8],
        signatureScheme: SignatureScheme,
        signature: [UInt8]
    ) {
        self.namedGroup = namedGroup
        self.publicKey = publicKey
        self.signatureScheme = signatureScheme
        self.signature = signature
    }

    /// Encode the EC params portion (for signing)
    public static func encodeParams(namedGroup: NamedGroup, publicKey: [UInt8]) throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()
        // ECParameters: curve_type = named_curve (3)
        writer.writeUInt8(0x03)
        // named_curve
        writer.writeUInt16(namedGroup.rawValue)
        // ECPoint
        try writer.dWriteVector8(publicKey)
        return writer.finishArray()
    }

    /// Encode the full ServerKeyExchange body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()

        // EC parameters
        writer.writeUInt8(0x03) // curve_type = named_curve
        writer.writeUInt16(namedGroup.rawValue)
        try writer.dWriteVector8(publicKey)

        // Signature
        writer.writeUInt8(signatureScheme.hashByte)
        writer.writeUInt8(signatureScheme.signatureByte)
        try writer.dWriteVector16(signature)

        return writer.finishArray()
    }

    /// Decode from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> ServerKeyExchange {
        var reader = ByteReader(data)

        // EC parameters
        let curveType = try reader.dReadUInt8()
        guard curveType == 0x03 else {
            throw DTLSWireError.dtls(.invalidServerKeyExchange("Expected named_curve type 3, got \(curveType)"))
        }
        let groupValue = try reader.dReadUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw DTLSWireError.dtls(.invalidServerKeyExchange("Unknown named group: 0x\(String(groupValue, radix: 16))"))
        }
        let publicKey = try reader.dReadVector8()

        // Signature
        let hashByte = try reader.dReadUInt8()
        let sigByte = try reader.dReadUInt8()
        let scheme = try SignatureScheme.from(hash: hashByte, signature: sigByte)
        let signature = try reader.dReadVector16()

        return ServerKeyExchange(
            namedGroup: group,
            publicKey: publicKey,
            signatureScheme: scheme,
            signature: signature
        )
    }
}
