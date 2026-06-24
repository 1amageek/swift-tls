/// Translates the facade `TLSConfiguration` into the engine
/// `TLSCore.TLSConfiguration` — the HOST X.509 validation strategy.
///
/// The facade is `[UInt8]`-currency and free of swift-crypto/swift-certificates
/// types; the engine config carries the real signing key, X.509 roots, and the
/// `(any Sendable)`-returning validator. This bridge does the one-time conversion
/// at handshake setup. It preserves every security-relevant field — verifyPeer,
/// trust roots, required client certificate, the mandatory CertificateVerify path,
/// and the custom validator — unchanged.
///
/// X.509 chain validation is structurally bound to swift-certificates (Foundation,
/// `X509Certificate.parse`), so this bridge is the HOST-ONLY validation strategy
/// (embedded-first-api.md §D hard-spot resolution): it is gated by
/// `#if canImport(Foundation)`. An Embedded build supplies the RFC-7250 raw-public-
/// key strategy (`P2PCoreDER`) instead. The `certificateValidator` user hook on
/// `TLSConfiguration` is preserved by both strategies.
#if canImport(Foundation)
import Foundation
import TLSCore
import TLSWireCore
import TLSEngineCore

extension TLSConfiguration {
    /// Builds the cored CLIENT engine configuration (host X.509 + signing strategy).
    func makeClientEngineConfiguration() throws(TLSError) -> TLSEngineConfiguration<TLSCryptoProvider> {
        try makeEngineConfiguration().makeClientEngineConfiguration()
    }

    /// Builds the cored SERVER engine configuration (host X.509 + signing strategy).
    func makeServerEngineConfiguration() throws(TLSError) -> TLSEngineConfiguration<TLSCryptoProvider> {
        try makeEngineConfiguration().makeServerEngineConfiguration()
    }

    /// Build the engine configuration. Throws `TLSError` for invalid material
    /// (e.g. a malformed signing key), never silently dropping it.
    func makeEngineConfiguration() throws(TLSError) -> TLSCore.TLSConfiguration {
        var engine = TLSCore.TLSConfiguration()
        engine.serverName = serverName
        engine.alpnProtocols = alpnProtocols
        engine.verifyPeer = verifyPeer
        engine.requireClientCertificate = requireClientCertificate

        // Identity: signing key + certificate chain (or raw public key).
        if let identity {
            do {
                engine.signingKey = try SigningKey(
                    rawPrivateKey: identity.privateKey,
                    scheme: identity.keyType.engineScheme
                )
            } catch {
                throw .invalidConfiguration(reason: "invalid signing key: \(error)")
            }
            engine.certificateChain = identity.certificateChain.map { Data($0.der) }
        }

        // Certificate types (RFC 7250).
        engine.localCertificateTypes = certificateTypes.local.map(\.engineType)
        engine.peerCertificateTypes = certificateTypes.peer.map(\.engineType)

        // Trust roots.
        if !trustRoots.x509Roots.isEmpty {
            do {
                engine.trustedRootCertificates = try trustRoots.x509Roots.map {
                    try X509Certificate.parse(from: Data($0.der))
                }
            } catch {
                throw .invalidConfiguration(reason: "invalid trust root: \(error)")
            }
        }
        if !trustRoots.rawPublicKeys.isEmpty {
            engine.trustedRawPublicKeys = trustRoots.rawPublicKeys.map { Data($0.der) }
        }

        // Custom validator: bridge [Data] -> [Certificate] and PeerIdentity? -> any Sendable?.
        // The existential `certificateValidator` feeds the legacy `TLS13Handler` path;
        // the cored engine path uses `peerIdentifierValidator`, which runs the SAME
        // user validator but surfaces only the Embedded-clean identifier bytes.
        if let validator = certificateValidator {
            engine.certificateValidator = { @Sendable (chain: [Data]) throws -> (any Sendable)? in
                let certificates = chain.map { Certificate(der: [UInt8]($0)) }
                let identity: PeerIdentity?
                do {
                    identity = try validator(certificates)
                } catch let tlsError {
                    throw tlsError
                }
                return identity
            }
            engine.peerIdentifierValidator = { @Sendable (chain: [Data]) throws -> [UInt8]? in
                let certificates = chain.map { Certificate(der: [UInt8]($0)) }
                let identity: PeerIdentity?
                do {
                    identity = try validator(certificates)
                } catch let tlsError {
                    throw tlsError
                }
                return identity?.identifier
            }
        }

        return engine
    }
}

extension TLSIdentity.KeyType {
    var engineScheme: SignatureScheme {
        switch self {
        case .ecdsaP256: return .ecdsa_secp256r1_sha256
        case .ecdsaP384: return .ecdsa_secp384r1_sha384
        case .ed25519:   return .ed25519
        }
    }
}

extension TLSCertificateTypes.CertificateType {
    var engineType: CertificateType {
        switch self {
        case .x509:         return .x509
        case .rawPublicKey: return .rawPublicKey
        }
    }
}
#endif // canImport(Foundation)
