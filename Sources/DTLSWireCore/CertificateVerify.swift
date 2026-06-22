/// DTLS 1.2 CertificateVerify (RFC 5246 Section 7.4.8)
///
/// struct {
///   digitally-signed struct {
///     opaque handshake_messages[handshake_messages_length];
///   };
/// } CertificateVerify;

import P2PCoreBytes
import TLSWireCore

/// DTLS 1.2 CertificateVerify message
public struct CertificateVerify: Sendable {
    /// Signature algorithm
    public let signatureScheme: SignatureScheme

    /// Signature over all handshake messages
    public let signature: [UInt8]

    public init(signatureScheme: SignatureScheme, signature: [UInt8]) {
        self.signatureScheme = signatureScheme
        self.signature = signature
    }

    /// Encode the CertificateVerify body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()
        writer.writeUInt8(signatureScheme.hashByte)
        writer.writeUInt8(signatureScheme.signatureByte)
        try writer.dWriteVector16(signature)
        return writer.finishArray()
    }

    /// Decode from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> CertificateVerify {
        var reader = ByteReader(data)
        let hashByte = try reader.dReadUInt8()
        let sigByte = try reader.dReadUInt8()
        let scheme = try SignatureScheme.from(hash: hashByte, signature: sigByte)
        let signature = try reader.dReadVector16()
        return CertificateVerify(signatureScheme: scheme, signature: signature)
    }
}
