/// A facade certificate value: a DER-encoded X.509 certificate or a bare
/// SubjectPublicKeyInfo (RFC 7250 raw public key).
///
/// The facade deliberately exposes only the DER bytes — never a swift-certificates
/// `X509.Certificate` type — so X.509 stays off the public surface and the same
/// value type works for both the host (X.509) and Embedded (raw-public-key)
/// validation strategies.
public struct Certificate: Sendable, Hashable {
    /// The DER-encoded certificate (X.509) or SubjectPublicKeyInfo (raw public key).
    public let der: [UInt8]

    public init(der: [UInt8]) {
        self.der = der
    }
}
