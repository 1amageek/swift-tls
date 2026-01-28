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

import Foundation
import Crypto
import TLSCore

/// DTLS 1.2 ServerKeyExchange message for ECDHE
public struct ServerKeyExchange: Sendable {
    /// Named curve used
    public let namedGroup: TLSCore.NamedGroup

    /// Server's ephemeral ECDH public key
    public let publicKey: Data

    /// Signature algorithm
    public let signatureScheme: TLSCore.SignatureScheme

    /// Signature over the params
    public let signature: Data

    public init(
        namedGroup: TLSCore.NamedGroup,
        publicKey: Data,
        signatureScheme: TLSCore.SignatureScheme,
        signature: Data
    ) {
        self.namedGroup = namedGroup
        self.publicKey = publicKey
        self.signatureScheme = signatureScheme
        self.signature = signature
    }

    /// Create and sign a ServerKeyExchange
    /// - Parameters:
    ///   - keyExchange: The ECDHE key pair
    ///   - signingKey: The server's signing key
    ///   - clientRandom: 32-byte client random
    ///   - serverRandom: 32-byte server random
    /// - Returns: Signed ServerKeyExchange
    public static func create(
        keyExchange: KeyExchange,
        signingKey: SigningKey,
        clientRandom: Data,
        serverRandom: Data
    ) throws -> ServerKeyExchange {
        let publicKeyBytes = keyExchange.publicKeyBytes
        let namedGroup = keyExchange.group

        // Build the data to sign:
        // client_random + server_random + curve_params + public_key
        let paramsData = encodeParams(namedGroup: namedGroup, publicKey: publicKeyBytes)
        let signedData = clientRandom + serverRandom + paramsData
        let signature = try signingKey.sign(signedData)

        return ServerKeyExchange(
            namedGroup: namedGroup,
            publicKey: publicKeyBytes,
            signatureScheme: signingKey.scheme,
            signature: signature
        )
    }

    /// Verify the signature
    public func verify(
        clientRandom: Data,
        serverRandom: Data,
        verificationKey: VerificationKey
    ) throws -> Bool {
        let paramsData = Self.encodeParams(namedGroup: namedGroup, publicKey: publicKey)
        let signedData = clientRandom + serverRandom + paramsData
        return try verificationKey.verify(signature: signature, for: signedData)
    }

    /// Encode the EC params portion (for signing)
    private static func encodeParams(namedGroup: TLSCore.NamedGroup, publicKey: Data) -> Data {
        var writer = TLSWriter()
        // ECParameters: curve_type = named_curve (3)
        writer.writeUInt8(0x03)
        // named_curve
        writer.writeUInt16(namedGroup.rawValue)
        // ECPoint
        writer.writeVector8(publicKey)
        return writer.finish()
    }

    /// Encode the full ServerKeyExchange body
    public func encode() -> Data {
        var writer = TLSWriter()

        // EC parameters
        writer.writeUInt8(0x03) // curve_type = named_curve
        writer.writeUInt16(namedGroup.rawValue)
        writer.writeVector8(publicKey)

        // Signature
        writer.writeUInt8(signatureScheme.hashByte)
        writer.writeUInt8(signatureScheme.signatureByte)
        writer.writeVector16(signature)

        return writer.finish()
    }

    /// Decode from body data
    public static func decode(from data: Data) throws -> ServerKeyExchange {
        var reader = TLSReader(data: data)

        // EC parameters
        let curveType = try reader.readUInt8()
        guard curveType == 0x03 else {
            throw DTLSError.invalidServerKeyExchange("Expected named_curve type 3, got \(curveType)")
        }
        let groupValue = try reader.readUInt16()
        guard let group = TLSCore.NamedGroup(rawValue: groupValue) else {
            throw DTLSError.invalidServerKeyExchange("Unknown named group: 0x\(String(groupValue, radix: 16))")
        }
        let publicKey = try reader.readVector8()

        // Signature
        let hashByte = try reader.readUInt8()
        let sigByte = try reader.readUInt8()
        let scheme = SignatureScheme.from(hash: hashByte, signature: sigByte)
        let signature = try reader.readVector16()

        return ServerKeyExchange(
            namedGroup: group,
            publicKey: publicKey,
            signatureScheme: scheme,
            signature: signature
        )
    }
}

// MARK: - SignatureScheme helpers

extension SignatureScheme {
    /// Hash algorithm byte for TLS 1.2 signature
    var hashByte: UInt8 {
        UInt8(rawValue >> 8)
    }

    /// Signature algorithm byte for TLS 1.2 signature
    var signatureByte: UInt8 {
        UInt8(rawValue & 0xFF)
    }

    /// Construct from hash + signature algorithm bytes
    static func from(hash: UInt8, signature: UInt8) -> SignatureScheme {
        let value = UInt16(hash) << 8 | UInt16(signature)
        return SignatureScheme(rawValue: value) ?? .ecdsa_secp256r1_sha256
    }
}
