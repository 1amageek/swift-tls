/// Configuration for `DTLSClient`/`DTLSServer` (DTLS 1.2 over UDP datagrams).
///
/// DTLS in this stack authenticates with an ECDSA P-256 certificate (WebRTC /
/// libp2p convention). The identity carries the DER leaf certificate plus the
/// raw 32-byte P-256 private key.
import TLSCryptoProvider
import SSLDTLS

public struct DTLSConfiguration: Sendable {
    /// The local DTLS identity (ECDSA P-256 certificate + raw private key).
    /// `keyType` must be `.ecdsaP256`.
    public var identity: TLSIdentity

    /// Require the peer to present a certificate (mutual authentication).
    /// WebRTC/libp2p deployments set this to `true`.
    public var requireClientCertificate: Bool

    /// Required SRTP negotiation, or `nil` for ordinary DTLS application data.
    public var srtp: DTLSSRTPConfiguration?

    public init(
        identity: TLSIdentity,
        requireClientCertificate: Bool = true,
        srtp: DTLSSRTPConfiguration? = nil
    ) {
        self.identity = identity
        self.requireClientCertificate = requireClientCertificate
        self.srtp = srtp
    }
}
