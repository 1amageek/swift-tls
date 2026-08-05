import SSLCore
import SSLTLS
import TLSTypes

/// A request for one private-key CertificateVerify operation.
public struct TLSSignatureRequest: Sendable, Hashable {
    public let token: TLSCapabilityToken
    public let role: TLSRole
    public let credentialIdentifier: [UInt8]
    public let signatureScheme: TLSSignatureScheme
    public let message: [UInt8]

    init(core: TLS13SignatureRequest) {
        self.token = TLSCapabilityToken(core: core.token)
        self.role = core.role == .client ? .client : .server
        self.credentialIdentifier = core.credentialIdentifier.span.toArray()
        self.signatureScheme = TLSSignatureScheme(rawValue: core.signatureScheme.rawValue)
        self.message = core.message.span.toArray()
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
