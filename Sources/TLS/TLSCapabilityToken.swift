import SSLTLS

/// Correlates one public capability response with the suspended TLS session.
public struct TLSCapabilityToken: Sendable, Hashable {
    public let sequence: UInt64
    public let kind: TLSCapabilityKind

    let core: TLS13CapabilityToken

    init(core: TLS13CapabilityToken) {
        self.core = core
        self.sequence = core.sequence
        self.kind = TLSCapabilityKind(core: core.kind)
    }
}

/// The category of external work requested by a TLS session.
public enum TLSCapabilityKind: UInt8, Sendable, Hashable {
    case peerTrustEvaluation
    case credentialSelection
    case signature

    fileprivate init(core: TLS13CapabilityKind) {
        switch core {
        case .peerTrustEvaluation: self = .peerTrustEvaluation
        case .credentialSelection: self = .credentialSelection
        case .signature: self = .signature
        }
    }
}
