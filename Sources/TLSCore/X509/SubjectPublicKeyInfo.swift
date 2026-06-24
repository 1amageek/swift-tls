/// SubjectPublicKeyInfo Codec (RFC 5280 Section 4.1.2.7, RFC 7250)
///
/// Encodes and decodes the DER SubjectPublicKeyInfo structure used as
/// the certificate payload for Raw Public Key authentication (RFC 7250).
///
/// ```
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm        AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
/// }
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm  OBJECT IDENTIFIER,
///     parameters ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```

import Foundation
import TLSWireCore
import Crypto
import SwiftASN1

/// A parsed SubjectPublicKeyInfo with both the verification key and the
/// exact DER bytes (used for byte-level trust comparison in RFC 7250).
package struct SubjectPublicKeyInfo: Sendable {

    /// The verification key parsed from the structure
    public let verificationKey: VerificationKey

    /// The exact DER encoding of the SubjectPublicKeyInfo
    public let derRepresentation: Data

    // MARK: - Object Identifiers

    /// id-ecPublicKey (RFC 5480)
    static let ecPublicKeyOID: ASN1ObjectIdentifier = [1, 2, 840, 10045, 2, 1]

    /// secp256r1 / prime256v1 (RFC 5480)
    static let p256OID: ASN1ObjectIdentifier = [1, 2, 840, 10045, 3, 1, 7]

    /// secp384r1 (RFC 5480)
    static let p384OID: ASN1ObjectIdentifier = [1, 3, 132, 0, 34]

    /// id-Ed25519 (RFC 8410)
    static let ed25519OID: ASN1ObjectIdentifier = [1, 3, 101, 112]

    // MARK: - Encoding

    /// Encodes a public key as DER SubjectPublicKeyInfo.
    ///
    /// - Parameters:
    ///   - scheme: The signature scheme identifying the key type
    ///   - publicKeyBytes: The key bytes (x963 for EC, raw for Ed25519)
    /// - Returns: The DER-encoded SubjectPublicKeyInfo
    public static func encode(scheme: SignatureScheme, publicKeyBytes: Data) throws -> Data {
        let algorithmOID: ASN1ObjectIdentifier
        let parametersOID: ASN1ObjectIdentifier?

        switch scheme {
        case .ecdsa_secp256r1_sha256:
            algorithmOID = ecPublicKeyOID
            parametersOID = p256OID
        case .ecdsa_secp384r1_sha384:
            algorithmOID = ecPublicKeyOID
            parametersOID = p384OID
        case .ed25519:
            algorithmOID = ed25519OID
            parametersOID = nil
        default:
            throw SignatureError.unsupportedScheme(scheme)
        }

        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { spki in
            try spki.appendConstructedNode(identifier: .sequence) { algorithm in
                try algorithm.serialize(algorithmOID)
                if let parametersOID {
                    try algorithm.serialize(parametersOID)
                }
            }
            try spki.serialize(ASN1BitString(bytes: ArraySlice(publicKeyBytes)))
        }
        return Data(serializer.serializedBytes)
    }

    /// Encodes a signing key's public key as DER SubjectPublicKeyInfo.
    public static func encode(signingKey: any TLSSigningKey) throws -> Data {
        try encode(scheme: signingKey.scheme, publicKeyBytes: signingKey.publicKeyBytes)
    }

    // MARK: - Decoding

    /// Decodes DER SubjectPublicKeyInfo into a verification key.
    ///
    /// - Parameter data: The DER-encoded SubjectPublicKeyInfo
    /// - Returns: The parsed structure
    /// - Throws: `SignatureError.invalidPublicKey` for malformed or
    ///   unsupported structures
    public static func decode(from data: Data) throws -> SubjectPublicKeyInfo {
        let rootNode: ASN1Node
        do {
            rootNode = try DER.parse(Array(data))
        } catch {
            throw SignatureError.invalidPublicKey("SubjectPublicKeyInfo: malformed DER: \(error)")
        }

        let algorithmOID: ASN1ObjectIdentifier
        let parametersOID: ASN1ObjectIdentifier?
        let keyBitString: ASN1BitString
        do {
            (algorithmOID, parametersOID, keyBitString) = try DER.sequence(
                rootNode, identifier: .sequence
            ) { nodes -> (ASN1ObjectIdentifier, ASN1ObjectIdentifier?, ASN1BitString) in
                guard let algorithmNode = nodes.next() else {
                    throw SignatureError.invalidPublicKey("SubjectPublicKeyInfo: missing AlgorithmIdentifier")
                }
                let (oid, params) = try DER.sequence(
                    algorithmNode, identifier: .sequence
                ) { algorithmNodes -> (ASN1ObjectIdentifier, ASN1ObjectIdentifier?) in
                    let oid = try ASN1ObjectIdentifier(derEncoded: &algorithmNodes)
                    var params: ASN1ObjectIdentifier?
                    if let parametersNode = algorithmNodes.next() {
                        params = try ASN1ObjectIdentifier(derEncoded: parametersNode)
                    }
                    return (oid, params)
                }
                let bitString = try ASN1BitString(derEncoded: &nodes)
                return (oid, params, bitString)
            }
        } catch let error as SignatureError {
            throw error
        } catch {
            throw SignatureError.invalidPublicKey("SubjectPublicKeyInfo: invalid structure: \(error)")
        }

        guard keyBitString.paddingBits == 0 else {
            throw SignatureError.invalidPublicKey("SubjectPublicKeyInfo: unexpected padding bits in key")
        }
        let keyBytes = Data(keyBitString.bytes)

        let verificationKey: VerificationKey
        switch algorithmOID {
        case ecPublicKeyOID:
            switch parametersOID {
            case p256OID:
                verificationKey = try VerificationKey(
                    publicKeyBytes: keyBytes, scheme: .ecdsa_secp256r1_sha256
                )
            case p384OID:
                verificationKey = try VerificationKey(
                    publicKeyBytes: keyBytes, scheme: .ecdsa_secp384r1_sha384
                )
            default:
                throw SignatureError.invalidPublicKey(
                    "SubjectPublicKeyInfo: unsupported EC curve \(String(describing: parametersOID))"
                )
            }
        case ed25519OID:
            // RFC 8410 Section 3: parameters MUST be absent for Ed25519
            guard parametersOID == nil else {
                throw SignatureError.invalidPublicKey("SubjectPublicKeyInfo: Ed25519 must not have parameters")
            }
            verificationKey = try VerificationKey(publicKeyBytes: keyBytes, scheme: .ed25519)
        default:
            throw SignatureError.invalidPublicKey(
                "SubjectPublicKeyInfo: unsupported algorithm \(algorithmOID)"
            )
        }

        return SubjectPublicKeyInfo(verificationKey: verificationKey, derRepresentation: data)
    }
}
