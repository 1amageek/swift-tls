/// The EMBEDDED raw-public-key (RFC 7250) strategy for the cored ``TLSEngineCore``
/// engines — the Embedded-Swift counterpart of `TLSCore.TLSEngineHostStrategy`.
///
/// Builds a `TLSEngineConfiguration<TLSCryptoProvider>` from the facade
/// `TLSConfiguration` WITHOUT swift-certificates / Foundation. The engine's injected
/// seams are filled with the Embedded crypto provider + `P2PCoreDER`:
///
/// - `sign`             — signs the engine-built CertificateVerify content with the
///   configured raw private key through the `TLSCryptoProvider` ECDSA/Ed25519 scheme
///   (DER for ECDSA, raw for Ed25519 — the wire encoding).
/// - `resolvePeerKey`   — parses the peer leaf's SubjectPublicKeyInfo via
///   `P2PCoreDER.SubjectPublicKeyInfoDER` to recover the raw public key + scheme for
///   the in-core CertificateVerify proof-of-possession check.
/// - `validateCertificate` — runs the caller-injected identifier validator (libp2p
///   PeerID extraction) AFTER the in-core proof-of-possession check; higher-level
///   chain/identity validation is the caller's responsibility (the libp2p RPK model).
///
/// X.509 chain validation needs swift-certificates (Foundation) and is NOT available
/// in Embedded mode: a peer presenting a full X.509 leaf (not a bare SPKI) yields a
/// `nil` peer key from `resolvePeerKey`, which the core rejects FAIL-CLOSED. The
/// Embedded path therefore serves the raw-public-key (`.rawPublicKey`) deployments
/// (libp2p / WebRTC), exactly as the host strategy's RFC-7250 branch does.
///
/// Selected via `#if hasFeature(Embedded)` (Embedded) — the host build uses
/// `TLSConfigurationBridge` + `TLSEngineHostStrategy` instead.

#if hasFeature(Embedded)
import P2PCoreBytes
import P2PCoreCrypto
import P2PCoreDER
import P2PCryptoEmbedded
import TLSWireCore
import TLSCryptoCore
import TLSCryptoProvider
import TLSEngineCore

extension TLSConfiguration {

    /// Builds the cored CLIENT engine configuration (Embedded RPK strategy).
    func makeClientEngineConfiguration() throws(TLSError) -> TLSEngineConfiguration<TLSCryptoProvider> {
        try makeEmbeddedEngineConfiguration()
    }

    /// Builds the cored SERVER engine configuration (Embedded RPK strategy).
    func makeServerEngineConfiguration() throws(TLSError) -> TLSEngineConfiguration<TLSCryptoProvider> {
        try makeEmbeddedEngineConfiguration()
    }

    private func makeEmbeddedEngineConfiguration() throws(TLSError) -> TLSEngineConfiguration<TLSCryptoProvider> {
        var engine = TLSEngineConfiguration<TLSCryptoProvider>()
        engine.serverName = serverName
        engine.alpnProtocols = alpnProtocols
        engine.verifyPeer = verifyPeer
        engine.requireClientCertificate = requireClientCertificate
        engine.localCertificateTypes = certificateTypes.local.map { $0.engineType }
        engine.peerCertificateTypes = certificateTypes.peer.map { $0.engineType }

        // Identity (signer + chain).
        if let identity {
            let scheme = identity.keyType.engineScheme
            engine.signingScheme = scheme
            engine.certificateChain = identity.certificateChain.map { $0.der }
            let privateKey = identity.privateKey
            // Validate the private key once, up front (fail loudly on bad material).
            do {
                try EmbeddedTLSSign.validateSigningKey(privateKey: privateKey, scheme: scheme)
            } catch {
                throw .invalidConfiguration(reason: "invalid signing key")
            }
            // The cross-type error-mapping lives in the named helper (a closure
            // literal cannot bind `any Error` under Embedded).
            engine.sign = { @Sendable (signedContent: [UInt8], scheme: TLSWireCore.SignatureScheme) throws(TLSEngineError) -> [UInt8] in
                try EmbeddedTLSSeams.signCertVerify(content: signedContent, privateKey: privateKey, scheme: scheme)
            }
        }

        // Peer-key resolution: parse the leaf SubjectPublicKeyInfo (RFC 7250).
        engine.resolvePeerKey = { @Sendable (chain: [[UInt8]]) -> (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)? in
            EmbeddedTLSPeerKey.resolve(chain: chain)
        }

        // Caller-injected validator (libp2p PeerID). Runs AFTER the in-core
        // proof-of-possession check; a throw aborts fail-closed. Only the
        // Embedded-clean identifier bytes are threaded into the engine.
        if let validator = certificateValidator {
            engine.validateCertificate = { @Sendable (chain: [[UInt8]]) throws(TLSEngineError) -> [UInt8]? in
                try EmbeddedTLSSeams.runValidator(validator, chain: chain)
            }
        }

        return engine
    }
}

/// Embedded raw private-key signing over the `TLSCryptoProvider` ECDSA / Ed25519
/// schemes. Signs the engine-built CertificateVerify content directly (the schemes
/// hash it internally), producing the wire signature (DER for ECDSA, raw Ed25519).
enum EmbeddedTLSSign {

    /// Validates that `privateKey` is importable for `scheme` (throws otherwise).
    static func validateSigningKey(privateKey: [UInt8], scheme: TLSWireCore.SignatureScheme) throws(TLSSignatureCoreError) {
        switch scheme {
        case .ecdsa_secp256r1_sha256:
            do { _ = try TLSCryptoProvider.P256Signature.signingKey(rawRepresentation: privateKey.span) }
            catch { throw .crypto(error) }
        case .ecdsa_secp384r1_sha384:
            do { _ = try TLSCryptoProvider.P384Signature.signingKey(rawRepresentation: privateKey.span) }
            catch { throw .crypto(error) }
        case .ed25519:
            do { _ = try TLSCryptoProvider.Ed25519.signingKey(rawRepresentation: privateKey.span) }
            catch { throw .crypto(error) }
        default:
            throw .unsupportedScheme
        }
    }

    /// Signs `content` (the full CertificateVerify signed input) with `privateKey`.
    /// The provider ECDSA scheme DER-encodes; Ed25519 emits a raw 64-byte signature —
    /// exactly the CertificateVerify wire encoding. The `do` blocks contain ONLY the
    /// provider crypto calls (which throw `CryptoError`), so the implicit `catch`
    /// binds `CryptoError` (Embedded-clean — no `any Error`).
    static func sign(content: [UInt8], privateKey: [UInt8], scheme: TLSWireCore.SignatureScheme) throws(TLSSignatureCoreError) -> [UInt8] {
        switch scheme {
        case .ecdsa_secp256r1_sha256:
            do {
                let key = try TLSCryptoProvider.P256Signature.signingKey(rawRepresentation: privateKey.span)
                return try TLSCryptoProvider.P256Signature.sign(content.span, with: key)
            } catch { throw .crypto(error) }
        case .ecdsa_secp384r1_sha384:
            do {
                let key = try TLSCryptoProvider.P384Signature.signingKey(rawRepresentation: privateKey.span)
                return try TLSCryptoProvider.P384Signature.sign(content.span, with: key)
            } catch { throw .crypto(error) }
        case .ed25519:
            do {
                let key = try TLSCryptoProvider.Ed25519.signingKey(rawRepresentation: privateKey.span)
                return try TLSCryptoProvider.Ed25519.sign(content.span, with: key)
            } catch { throw .crypto(error) }
        default:
            throw .unsupportedScheme
        }
    }
}

/// Embedded peer-key resolution: recover the raw public key + scheme from the peer
/// leaf's SubjectPublicKeyInfo (RFC 7250 raw public key). FAIL-CLOSED — an
/// unparseable SPKI (e.g. a full X.509 leaf, which Embedded cannot parse) or an
/// unsupported key type yields `nil`, which the core rejects.
enum EmbeddedTLSPeerKey {
    static func resolve(chain: [[UInt8]]) -> (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)? {
        guard let leaf = chain.first else { return nil }
        let parsed: SubjectPublicKeyInfoDER.Parsed
        do {
            parsed = try SubjectPublicKeyInfoDER.parse(leaf)
        } catch {
            return nil
        }
        switch parsed.curve {
        case .p256:    return (parsed.keyBytes, .ecdsa_secp256r1_sha256)
        case .p384:    return (parsed.keyBytes, .ecdsa_secp384r1_sha384)
        case .ed25519: return (parsed.keyBytes, .ed25519)
        }
    }
}

/// Named seam helpers that perform the cross-type typed-throws error mapping for the
/// engine `sign` / `validateCertificate` closures. The mapping `do/catch` must live
/// in a named function — Embedded Swift rejects a cross-type `catch` inside a closure
/// literal (it would bind `any Error`).
enum EmbeddedTLSSeams {

    /// Signs the CertificateVerify content, mapping a signing failure to the engine
    /// error (fail-closed — never a fabricated signature).
    static func signCertVerify(
        content: [UInt8],
        privateKey: [UInt8],
        scheme: TLSWireCore.SignatureScheme
    ) throws(TLSEngineError) -> [UInt8] {
        do {
            return try EmbeddedTLSSign.sign(content: content, privateKey: privateKey, scheme: scheme)
        } catch {
            throw .verificationFailed(reason: "CertificateVerify signing failed")
        }
    }

    /// Runs the caller-injected validator, mapping a rejection (a `TLSError` throw) to
    /// the engine error (fail-closed). Returns the validated peer's identifier bytes.
    static func runValidator(
        _ validator: @Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?,
        chain: [[UInt8]]
    ) throws(TLSEngineError) -> [UInt8]? {
        let certificates = chain.map { Certificate(der: $0) }
        do {
            let identity = try validator(certificates)
            return identity?.identifier
        } catch {
            throw .verificationFailed(reason: "custom certificate validator rejected the peer")
        }
    }
}
#endif // hasFeature(Embedded)
