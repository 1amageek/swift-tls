import SSLCore
import SSLTLS

/// A response correlated to a previously emitted ``TLSCapabilityRequest``.
public enum TLSCapabilityResponse: Sendable, Hashable {
    case peerTrustAccepted(TLSCapabilityToken)
    case peerTrustRejected(TLSCapabilityToken)
    case credentialSelected(TLSCapabilityToken, TLSCredential)
    case credentialUnavailable(TLSCapabilityToken)
    case signature(TLSCapabilityToken, [UInt8])
    case signatureRejected(TLSCapabilityToken)

    func core(
        verificationInstant: VerificationInstant
    ) throws(TLSError) -> TLS13CapabilityResponse {
        do {
            switch self {
            case .peerTrustAccepted(let token):
                return .peerTrustAccepted(token.core)
            case .peerTrustRejected(let token):
                return .peerTrustRejected(token.core)
            case .credentialUnavailable(let token):
                return .credentialUnavailable(token.core)
            case .signatureRejected(let token):
                return .signatureRejected(token.core)
            case .signature(let token, let signature):
                return .signature(token.core, OwnedBytes(consuming: ContiguousArray(signature)))
            case .credentialSelected(let token, let credential):
                let identifier = ContiguousArray(credential.identifier)
                guard let scheme = TLS13SignatureScheme(rawValue: credential.signatureScheme.rawValue) else {
                    throw TLSError.invalidCapabilityResponse(reason: "Unsupported signature scheme")
                }
                switch credential.certificateType {
                case .x509:
                    let entries = try makeCertificateEntries(credential.certificateChain)
                    let descriptor = try TLS13CredentialDescriptor(
                        identifier: identifier.span,
                        certificateEntries: entries,
                        signatureScheme: scheme,
                        verificationInstant: verificationInstant
                    )
                    return .credentialSelected(token.core, descriptor)
                case .rawPublicKey:
                    guard let rawPublicKey = credential.rawPublicKey else {
                        throw TLSError.invalidCapabilityResponse(
                            reason: "raw-public-key credential is missing SubjectPublicKeyInfo"
                        )
                    }
                    let descriptor = try TLS13CredentialDescriptor(
                        identifier: identifier.span,
                        rawPublicKeyDER: rawPublicKey.der.span,
                        signatureScheme: scheme
                    )
                    return .credentialSelected(token.core, descriptor)
                }
            }
        } catch let error as TLSError {
            throw error
        } catch {
            throw .invalidCapabilityResponse(reason: "credential is not valid for TLS")
        }
    }

    private func makeCertificateEntries(
        _ certificates: [Certificate]
    ) throws(TLSError) -> ContiguousArray<TLS13CertificateEntry> {
        guard !certificates.isEmpty else {
            throw .invalidCapabilityResponse(reason: "certificate chain is empty")
        }
        var entries = ContiguousArray<TLS13CertificateEntry>()
        entries.reserveCapacity(certificates.count)
        for certificate in certificates {
            do {
                entries.append(try TLS13CertificateEntry(certificateDER: certificate.der.span))
            } catch {
                throw .invalidCapabilityResponse(reason: "certificate chain is malformed")
            }
        }
        return entries
    }
}
