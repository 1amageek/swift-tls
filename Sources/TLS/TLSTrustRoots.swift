/// The set of roots used to authenticate the peer.
///
/// Holds X.509 trust-anchor DER certificates (host validation) and/or trusted raw
/// public keys (RFC 7250, Embedded-clean). `verifyPeer` on `TLSConfiguration`
/// controls whether peer authentication is enforced; this value supplies the
/// anchors when it is.
public struct TLSTrustRoots: Sendable, Hashable {
    /// Trusted X.509 root certificates (DER-encoded).
    public let x509Roots: [Certificate]

    /// Trusted raw public keys (DER-encoded SubjectPublicKeyInfo, RFC 7250).
    public let rawPublicKeys: [Certificate]

    public init(x509Roots: [Certificate] = [], rawPublicKeys: [Certificate] = []) {
        self.x509Roots = x509Roots
        self.rawPublicKeys = rawPublicKeys
    }

    /// An empty trust store (used with a custom validator or `verifyPeer == false`).
    public static let none = TLSTrustRoots()
}
