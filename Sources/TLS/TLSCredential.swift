import SSLCore
import SSLTLS
import SSLX509

/// A credential selected for one suspended TLS handshake.
public struct TLSCredential: Sendable, Hashable {
    public let identifier: [UInt8]
    public let certificateChain: [Certificate]
    public let rawPublicKey: Certificate?
    public let certificateType: TLSCertificateTypes.CertificateType
    public let signatureScheme: TLSSignatureScheme

    public init(
        identifier: [UInt8],
        certificateChain: [Certificate] = [],
        rawPublicKey: Certificate? = nil,
        certificateType: TLSCertificateTypes.CertificateType,
        signatureScheme: TLSSignatureScheme
    ) {
        self.identifier = identifier
        self.certificateChain = certificateChain
        self.rawPublicKey = rawPublicKey
        self.certificateType = certificateType
        self.signatureScheme = signatureScheme
    }

    init(core: TLS13CredentialDescriptor) {
        var chain: [Certificate] = []
        chain.reserveCapacity(core.certificateEntries.count)
        for entry in core.certificateEntries {
            chain.append(Certificate(der: entry.certificate.span.toArray()))
        }
        let raw: Certificate? = core.rawPublicKey.map {
            Certificate(der: $0.span.toArray())
        }
        self.init(
            identifier: core.identifier.span.toArray(),
            certificateChain: chain,
            rawPublicKey: raw,
            certificateType: core.certificateType == .x509 ? .x509 : .rawPublicKey,
            signatureScheme: TLSSignatureScheme(rawValue: core.signatureScheme.rawValue)
        )
    }
}

private extension Span where Element == UInt8 {
    func toArray() -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        var index = 0
        while index < count {
            result.append(self[index])
            index += 1
        }
        return result
    }
}
