/// The EMBEDDED ECDHE + raw-public-key strategy for the cored ``DTLSEngineCore``
/// engines — the Embedded-Swift counterpart of `DTLSCore.DTLSEngineHostStrategy`.
///
/// Builds a `DTLSEngineConfiguration<TLSCryptoProvider>` from the facade
/// `DTLSConfiguration` WITHOUT swift-certificates / Foundation. The engine's injected
/// seams are filled with the Embedded crypto provider + `P2PCoreDER`:
///
/// - `randomBytes`         — the provider CSPRNG (`TLSCryptoProvider.random`).
/// - `ecdheGenerate`/`ecdheAgree` — `TLSKeyExchange<TLSCryptoProvider>` (P-256).
/// - `sign`                — ECDSA-P256-DER over the engine-built data through the
///   provider scheme (ServerKeyExchange params / CertificateVerify hash).
/// - `verifyPeerSignature` — parse the peer leaf's SubjectPublicKeyInfo (RFC 7250)
///   via `P2PCoreDER`, then verify the DER signature over `data`. FAIL-CLOSED: an
///   unparseable SPKI (e.g. a full X.509 leaf, which Embedded cannot parse) throws.
/// - `makeCookie`/`verifyCookie` — HMAC-SHA256 over a process-lifetime random
///   cookie secret (the provider MAC); a presented cookie that fails verification is
///   rejected by the core.
///
/// DTLS in this stack uses ECDSA P-256 only; a non-P256 identity is rejected up
/// front (no silent fallback). X.509 chain validation is unavailable in Embedded —
/// the peer must present a bare SubjectPublicKeyInfo (libp2p RPK); a full X.509 leaf
/// fails `verifyPeerSignature` fail-closed.
///
/// Selected via `#if hasFeature(Embedded)` (Embedded).

#if hasFeature(Embedded)
import P2PCoreBytes
import P2PCoreCrypto
import P2PCoreDER
import P2PCryptoEmbedded
import TLSWireCore
import DTLSWireCore
import TLSCryptoCore
import TLSCryptoProvider
import DTLSEngineCore

extension DTLSConfiguration {

    /// Build the cored DTLS engine configuration (EMBEDDED RPK strategy).
    func makeDTLSEngineConfiguration() throws(TLSError) -> DTLSEngineConfiguration<TLSCryptoProvider> {
        guard identity.keyType == .ecdsaP256 else {
            throw .invalidConfiguration(reason: "DTLS requires an ECDSA P-256 identity")
        }
        guard let leaf = identity.certificateChain.first else {
            throw .invalidConfiguration(reason: "DTLS identity has no certificate")
        }
        let privateKey = identity.privateKey
        // Validate the signing key once, up front (fail loudly on bad material).
        do {
            _ = try TLSCryptoProvider.P256Signature.signingKey(rawRepresentation: privateKey.span)
        } catch {
            throw .invalidConfiguration(reason: "invalid DTLS signing key")
        }

        var engine = DTLSEngineConfiguration<TLSCryptoProvider>(
            supportedCipherSuites: [.ecdheEcdsaWithAes128GcmSha256],
            requireClientCertificate: requireClientCertificate,
            certificateChainDER: [leaf.der],
            signingScheme: .ecdsa_secp256r1_sha256
        )

        // NOTE: the typed-throws error-mapping (`do/catch` converting one typed error
        // to another) is delegated to named static helpers in `EmbeddedDTLSSeams`.
        // Under Embedded Swift such a cross-type `catch` inside a CLOSURE literal binds
        // `any Error` (forbidden); the same code in a named function is fine. The
        // closures therefore just forward to the helpers.
        engine.randomBytes = { @Sendable (count: Int) -> [UInt8] in
            TLSCryptoProvider.random.randomBytes(count)
        }
        engine.ecdheGenerate = { @Sendable (group: NamedGroup) throws(DTLSEngineError) -> (publicKey: [UInt8], privateHandle: [UInt8]) in
            try EmbeddedDTLSSeams.ecdheGenerate(group: group)
        }
        engine.ecdheAgree = { @Sendable (group: NamedGroup, handle: [UInt8], peerPublicKey: [UInt8]) throws(DTLSEngineError) -> [UInt8] in
            try EmbeddedDTLSSeams.ecdheAgree(group: group, handle: handle, peerPublicKey: peerPublicKey)
        }
        engine.sign = { @Sendable (data: [UInt8]) throws(DTLSEngineError) -> [UInt8] in
            try EmbeddedDTLSSeams.sign(data: data, privateKey: privateKey)
        }
        engine.verifyPeerSignature = { @Sendable (chain: [[UInt8]], signature: [UInt8], data: [UInt8]) throws(DTLSEngineError) -> Bool in
            try EmbeddedDTLSSeams.verifyPeerSignature(chain: chain, signature: signature, data: data)
        }

        // HMAC-SHA256 cookie over a process-lifetime random secret (server only).
        // The same secret backs both make and verify; a presented cookie that fails
        // the MAC is rejected by the core (fail-closed).
        let cookieSecret = TLSCryptoProvider.random.randomBytes(32)
        engine.makeCookie = { @Sendable (material: [UInt8]) -> [UInt8] in
            TLSCryptoProvider.HMACSHA256.authenticationCode(for: material.span, key: cookieSecret.span)
        }
        engine.verifyCookie = { @Sendable (cookie: [UInt8], material: [UInt8]) -> Bool in
            TLSCryptoProvider.HMACSHA256.isValid(cookie.span, for: material.span, key: cookieSecret.span)
        }

        return engine
    }
}

/// Named static seam helpers for the Embedded DTLS strategy. The typed-throws
/// error-mapping `do/catch` lives here (in functions, not closures) because Embedded
/// Swift rejects a cross-type `catch` inside a closure literal.
enum EmbeddedDTLSSeams {

    static func ecdheGenerate(group: NamedGroup) throws(DTLSEngineError) -> (publicKey: [UInt8], privateHandle: [UInt8]) {
        do {
            let pair = try TLSKeyExchange<TLSCryptoProvider>.generate(for: group)
            return (publicKey: pair.publicKeyBytes, privateHandle: pair.privateKeyBytes)
        } catch {
            throw .protocolFailure(reason: "DTLS ECDHE key generation failed")
        }
    }

    static func ecdheAgree(group: NamedGroup, handle: [UInt8], peerPublicKey: [UInt8]) throws(DTLSEngineError) -> [UInt8] {
        do {
            return try TLSKeyExchange<TLSCryptoProvider>.sharedSecret(
                group: group,
                privateKeyBytes: handle.span,
                peerPublicKeyBytes: peerPublicKey.span
            )
        } catch {
            throw .protocolFailure(reason: "DTLS ECDHE agreement failed")
        }
    }

    static func sign(data: [UInt8], privateKey: [UInt8]) throws(DTLSEngineError) -> [UInt8] {
        do {
            let key = try TLSCryptoProvider.P256Signature.signingKey(rawRepresentation: privateKey.span)
            return try TLSCryptoProvider.P256Signature.sign(data.span, with: key)
        } catch {
            throw .verificationFailed(reason: "DTLS signing failed")
        }
    }

    static func verifyPeerSignature(chain: [[UInt8]], signature: [UInt8], data: [UInt8]) throws(DTLSEngineError) -> Bool {
        guard let peerLeaf = chain.first else {
            throw .verificationFailed(reason: "DTLS peer presented no certificate")
        }
        let parsed: SubjectPublicKeyInfoDER.Parsed
        do {
            parsed = try SubjectPublicKeyInfoDER.parse(peerLeaf)
        } catch {
            // A full X.509 leaf (not a bare SPKI) cannot be parsed in Embedded —
            // fail closed rather than silently accept.
            throw .verificationFailed(reason: "DTLS peer SPKI parse failed (X.509 unsupported in Embedded)")
        }
        guard parsed.curve == .p256 else {
            throw .verificationFailed(reason: "DTLS peer key is not ECDSA P-256")
        }
        let key: TLSCryptoProvider.P256Signature.VerifyingKey
        do {
            key = try TLSCryptoProvider.P256Signature.verifyingKey(rawRepresentation: parsed.keyBytes.span)
        } catch {
            throw .verificationFailed(reason: "DTLS peer key import failed")
        }
        return TLSCryptoProvider.P256Signature.isValid(signature: signature.span, for: data.span, with: key)
    }
}
#endif // hasFeature(Embedded)
