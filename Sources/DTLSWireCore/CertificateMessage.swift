/// DTLS 1.2 Certificate Message (RFC 5246 Section 7.4.2)
///
/// struct {
///   ASN.1Cert certificate_list<0..2^24-1>;
/// } Certificate;
///
/// ASN.1Cert = opaque<1..2^24-1>;

import P2PCoreBytes

/// DTLS 1.2 Certificate message carrying X.509 certificate chain
public struct CertificateMessage: Sendable {
    /// DER-encoded certificate chain (leaf first)
    public let certificates: [[UInt8]]

    public init(certificates: [[UInt8]]) {
        self.certificates = certificates
    }

    /// Encode the Certificate body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var certChain = ByteWriter()
        for cert in certificates {
            try certChain.dWriteVector24(cert)
        }

        var writer = ByteWriter()
        try writer.dWriteVector24(certChain.finishArray())
        return writer.finishArray()
    }

    /// Decode from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> CertificateMessage {
        var reader = ByteReader(data)
        let chainData = try reader.dReadVector24()

        var chainReader = ByteReader(chainData)
        var certs: [[UInt8]] = []
        while !chainReader.isAtEnd {
            let cert = try chainReader.dReadVector24()
            certs.append(cert)
        }

        return CertificateMessage(certificates: certs)
    }
}
