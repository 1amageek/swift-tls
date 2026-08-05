import SSLTLS

/// A terminal request emitted by a TLS session before it can continue.
public enum TLSCapabilityRequest: Sendable, Hashable {
    case peerTrustEvaluation(TLSPeerTrustEvaluationRequest)
    case credentialSelection(TLSCredentialSelectionRequest)
    case signature(TLSSignatureRequest)

    public var token: TLSCapabilityToken {
        switch self {
        case .peerTrustEvaluation(let request): request.token
        case .credentialSelection(let request): request.token
        case .signature(let request): request.token
        }
    }

    init(core: TLS13CapabilityRequest) {
        switch core {
        case .peerTrustEvaluation(let request):
            self = .peerTrustEvaluation(TLSPeerTrustEvaluationRequest(core: request))
        case .credentialSelection(let request):
            self = .credentialSelection(TLSCredentialSelectionRequest(core: request))
        case .signature(let request):
            self = .signature(TLSSignatureRequest(core: request))
        }
    }
}
