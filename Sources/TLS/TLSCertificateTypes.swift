/// Which certificate encodings this endpoint presents and accepts (RFC 7250).
///
/// `.x509` is the classic X.509 chain; `.rawPublicKey` is a bare
/// SubjectPublicKeyInfo. libp2p/WebRTC peer-authenticated deployments use
/// `.rawPublicKey`, which is the Embedded-clean path.
public struct TLSCertificateTypes: Sendable, Hashable {
    public enum CertificateType: Sendable, Hashable {
        case x509
        case rawPublicKey
    }

    /// Types we can present for our own authentication, in preference order.
    public let local: [CertificateType]

    /// Types we accept from the peer, in preference order.
    public let peer: [CertificateType]

    public init(local: [CertificateType] = [.x509], peer: [CertificateType] = [.x509]) {
        self.local = local
        self.peer = peer
    }

    /// The default classic X.509 setting.
    public static let x509 = TLSCertificateTypes(local: [.x509], peer: [.x509])

    /// The RFC 7250 raw-public-key setting (Embedded-clean, libp2p/WebRTC).
    public static let rawPublicKey = TLSCertificateTypes(
        local: [.rawPublicKey], peer: [.rawPublicKey]
    )
}
