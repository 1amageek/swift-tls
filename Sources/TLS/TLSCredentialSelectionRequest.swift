import SSLCore
import SSLTLS
import TLSTypes

/// A request to select a certificate and signing capability.
public struct TLSCredentialSelectionRequest: Sendable, Hashable {
    public let token: TLSCapabilityToken
    public let role: TLSRole
    public let serverName: [UInt8]?
    public let signatureSchemes: [TLSSignatureScheme]
    public let certificateTypes: [TLSCertificateTypes.CertificateType]
    public let certificateRequestContext: [UInt8]?
    public let verificationInstant: VerificationInstant

    init(core: TLS13CredentialSelectionRequest) {
        self.token = TLSCapabilityToken(core: core.token)
        self.role = core.role == .client ? .client : .server
        self.serverName = core.serverName?.span.toArray()
        self.signatureSchemes = core.signatureSchemes.map {
            TLSSignatureScheme(rawValue: $0.rawValue)
        }
        self.certificateTypes = core.certificateTypes.map {
            $0 == .x509 ? .x509 : .rawPublicKey
        }
        self.certificateRequestContext = core.certificateRequestContext?.span.toArray()
        self.verificationInstant = core.verificationInstant
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
