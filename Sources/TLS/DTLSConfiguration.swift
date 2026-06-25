/// Configuration for `DTLSClient`/`DTLSServer` (DTLS 1.2 over UDP datagrams).
///
/// DTLS in this stack authenticates with an ECDSA P-256 certificate (WebRTC /
/// libp2p convention). The identity carries the DER leaf certificate plus the
/// raw 32-byte P-256 private key.
import TLSCryptoProvider
import DTLSEngineCore
#if !hasFeature(Embedded)
import DTLSCore
#endif

public struct DTLSConfiguration: Sendable {
    /// The local DTLS identity (ECDSA P-256 certificate + raw private key).
    /// `keyType` must be `.ecdsaP256`.
    public var identity: TLSIdentity

    /// Require the peer to present a certificate (mutual authentication).
    /// WebRTC/libp2p deployments set this to `true`.
    public var requireClientCertificate: Bool

    public init(identity: TLSIdentity, requireClientCertificate: Bool = true) {
        self.identity = identity
        self.requireClientCertificate = requireClientCertificate
    }
}

#if !hasFeature(Embedded)
extension DTLSConfiguration {
    /// Build the engine `DTLSCertificate`. Throws `TLSError` for malformed
    /// material or a non-P256 key (no silent fallback).
    func makeCertificate() throws(TLSError) -> DTLSCertificate {
        guard identity.keyType == .ecdsaP256 else {
            throw .invalidConfiguration(reason: "DTLS requires an ECDSA P-256 identity")
        }
        guard let leaf = identity.certificateChain.first else {
            throw .invalidConfiguration(reason: "DTLS identity has no certificate")
        }
        do {
            return try DTLSCertificate(der: leaf.der, rawP256PrivateKey: identity.privateKey)
        } catch {
            throw .invalidConfiguration(reason: "invalid DTLS certificate: \(error)")
        }
    }

    /// Build the cored DTLS engine configuration (HOST swift-crypto / X.509 strategy).
    func makeDTLSEngineConfiguration() throws(TLSError) -> DTLSEngineConfiguration<TLSCryptoProvider> {
        let certificate = try makeCertificate()
        return certificate.makeDTLSEngineConfiguration(
            requireClientCertificate: requireClientCertificate
        )
    }
}
#endif // !hasFeature(Embedded)
