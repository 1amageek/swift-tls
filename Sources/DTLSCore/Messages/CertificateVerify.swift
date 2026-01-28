/// DTLS 1.2 CertificateVerify (RFC 5246 Section 7.4.8)
///
/// struct {
///   digitally-signed struct {
///     opaque handshake_messages[handshake_messages_length];
///   };
/// } CertificateVerify;

import Foundation
import TLSCore

/// DTLS 1.2 CertificateVerify message
public struct CertificateVerify: Sendable {
    /// Signature algorithm
    public let signatureScheme: TLSCore.SignatureScheme

    /// Signature over all handshake messages
    public let signature: Data

    public init(signatureScheme: TLSCore.SignatureScheme, signature: Data) {
        self.signatureScheme = signatureScheme
        self.signature = signature
    }

    /// Create a CertificateVerify by signing the handshake hash
    /// - Parameters:
    ///   - handshakeHash: Hash of all handshake messages so far
    ///   - signingKey: The client's signing key
    /// - Returns: Signed CertificateVerify
    public static func create(
        handshakeHash: Data,
        signingKey: SigningKey
    ) throws -> CertificateVerify {
        let signature = try signingKey.sign(handshakeHash)
        return CertificateVerify(
            signatureScheme: signingKey.scheme,
            signature: signature
        )
    }

    /// Verify the signature against the handshake hash
    public func verify(
        handshakeHash: Data,
        verificationKey: VerificationKey
    ) throws -> Bool {
        try verificationKey.verify(signature: signature, for: handshakeHash)
    }

    /// Encode the CertificateVerify body
    public func encode() -> Data {
        var writer = TLSWriter()
        writer.writeUInt8(signatureScheme.hashByte)
        writer.writeUInt8(signatureScheme.signatureByte)
        writer.writeVector16(signature)
        return writer.finish()
    }

    /// Decode from body data
    public static func decode(from data: Data) throws -> CertificateVerify {
        var reader = TLSReader(data: data)
        let hashByte = try reader.readUInt8()
        let sigByte = try reader.readUInt8()
        let scheme = SignatureScheme.from(hash: hashByte, signature: sigByte)
        let signature = try reader.readVector16()
        return CertificateVerify(signatureScheme: scheme, signature: signature)
    }
}
