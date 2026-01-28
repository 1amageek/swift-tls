/// DTLS 1.2 Certificate Message (RFC 5246 Section 7.4.2)
///
/// struct {
///   ASN.1Cert certificate_list<0..2^24-1>;
/// } Certificate;
///
/// ASN.1Cert = opaque<1..2^24-1>;

import Foundation
import TLSCore

/// DTLS 1.2 Certificate message carrying X.509 certificate chain
public struct CertificateMessage: Sendable {
    /// DER-encoded certificate chain (leaf first)
    public let certificates: [Data]

    public init(certificates: [Data]) {
        self.certificates = certificates
    }

    /// Create from a single DTLSCertificate
    public init(certificate: DTLSCertificate) {
        self.certificates = [certificate.derEncoded]
    }

    /// Encode the Certificate body
    public func encode() -> Data {
        var certChain = TLSWriter()
        for cert in certificates {
            certChain.writeVector24(cert)
        }

        var writer = TLSWriter()
        writer.writeVector24(certChain.finish())
        return writer.finish()
    }

    /// Decode from body data
    public static func decode(from data: Data) throws -> CertificateMessage {
        var reader = TLSReader(data: data)
        let chainData = try reader.readVector24()

        var chainReader = TLSReader(data: chainData)
        var certs: [Data] = []
        while chainReader.hasMore {
            let cert = try chainReader.readVector24()
            certs.append(cert)
        }

        return CertificateMessage(certificates: certs)
    }
}
