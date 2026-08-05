import SSLCore
import SSLTLS
import SSLX509
import TLSTypes

/// A request to authenticate a peer's certificate or raw public key.
public struct TLSPeerTrustEvaluationRequest: Sendable, Hashable {
    let coreRequest: TLS13PeerTrustEvaluationRequest
    public let token: TLSCapabilityToken
    public let peer: TLSRole
    public let certificates: [Certificate]
    public let certificateType: TLSCertificateTypes.CertificateType
    public let serverName: [UInt8]?
    public let verificationInstant: VerificationInstant

    init(core: TLS13PeerTrustEvaluationRequest) {
        self.coreRequest = core
        self.token = TLSCapabilityToken(core: core.token)
        self.peer = core.peer == .client ? .client : .server
        var certificates: [Certificate] = []
        certificates.reserveCapacity(core.certificateMessage.entries.count)
        for entry in core.certificateMessage.entries {
            certificates.append(Certificate(der: entry.certificate.span.toArray()))
        }
        self.certificates = certificates
        self.certificateType = core.certificateMessage.certificateType == .x509
            ? .x509
            : .rawPublicKey
        self.serverName = core.serverName?.span.toArray()
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
