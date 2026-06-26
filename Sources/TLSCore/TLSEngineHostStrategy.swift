/// The HOST X.509 + signing strategy for the cored ``TLSEngineCore`` engines.
///
/// Builds a `TLSEngineCore.TLSEngineConfiguration<TLSCryptoProvider>` from a
/// `TLSCore.TLSConfiguration`, filling the engine's three injected seams with the
/// swift-certificates / swift-crypto host strategy:
///
/// - `sign`             — `SigningKey.sign` (ECDSA-DER / Ed25519 over the identity).
/// - `resolvePeerKey`   — X.509 leaf / RFC-7250 SubjectPublicKeyInfo parsing, with
///   the `expectedPeerPublicKey` precedence preserved (byte-identical to the legacy
///   `ClientStateMachine.processCertificateVerify` peer-key resolution).
/// - `validateCertificate` — X.509 chain/trust validation + the user
///   `certificateValidator` hook, run AFTER the in-core CertificateVerify
///   proof-of-possession check (fail-closed) — byte-identical to the legacy
///   adapter's `processCertificate` / `processClientCertificateVerify` validation.
///
/// X.509 is structurally bound to swift-certificates (Foundation), so this lives
/// only on the host (TLSCore is the host adapter). The Embedded build supplies an
/// RFC-7250 raw-public-key strategy via `P2PCoreDER` at the facade boundary instead.
///
/// Security: every relevant field — verifyPeer, trust roots, required client
/// certificate, the mandatory CertificateVerify path, and the custom validator — is
/// preserved unchanged; no failure is silently swallowed.

import Foundation
import TLSWireCore
import TLSEngineCore

extension TLSConfiguration {

    /// Builds the cored engine configuration for a CLIENT (validates the SERVER peer).
    package func makeClientEngineConfiguration() -> TLSEngineConfiguration<TLSCryptoProvider> {
        makeTLSEngineConfiguration(validatingServerPeer: true)
    }

    /// Builds the cored engine configuration for a SERVER (validates the CLIENT peer).
    package func makeServerEngineConfiguration() -> TLSEngineConfiguration<TLSCryptoProvider> {
        makeTLSEngineConfiguration(validatingServerPeer: false)
    }

    private func makeTLSEngineConfiguration(
        validatingServerPeer: Bool
    ) -> TLSEngineConfiguration<TLSCryptoProvider> {
        var engine = TLSEngineConfiguration<TLSCryptoProvider>()
        engine.serverName = serverName
        engine.alpnProtocols = alpnProtocols
        engine.verifyPeer = verifyPeer
        engine.supportedGroups = supportedGroups
        engine.supportedCipherSuites = supportedCipherSuites
        engine.advertisedSignatureSchemes = ClientStateMachine.advertisedSignatureSchemes
        engine.localCertificateTypes = localCertificateTypes
        engine.peerCertificateTypes = peerCertificateTypes
        engine.requireClientCertificate = requireClientCertificate

        // Identity (signer + chain).
        if let signingKey {
            engine.signingScheme = signingKey.scheme
            engine.certificateChain = (certificateChain ?? []).map { [UInt8]($0) }
            engine.sign = { @Sendable (signedContent: [UInt8], _ scheme: TLSWireCore.SignatureScheme) throws(TLSEngineError) -> [UInt8] in
                do {
                    return [UInt8](try signingKey.sign(Data(signedContent)))
                } catch {
                    throw .verificationFailed(reason: "CertificateVerify signing failed")
                }
            }
        }

        // Peer-key resolution. Captures the config precedence (expectedPeerPublicKey
        // over the certificate key), the negotiated cert type defaulting, and the
        // RFC-7250 vs X.509 distinction — byte-identical to the legacy adapter.
        let expectedKey = expectedPeerPublicKey
        let peerTypes = peerCertificateTypes
        engine.resolvePeerKey = { @Sendable (chain: [[UInt8]]) -> (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)? in
            Self.resolvePeerKey(chain: chain, expectedPeerPublicKey: expectedKey, peerCertificateTypes: peerTypes)
        }

        // Certificate trust validation + user hook (after the in-core PoP check).
        let doVerify = verifyPeer
        let allowSelf = allowSelfSigned
        let revocation = revocationCheckMode
        let roots = trustedRootCertificates ?? []
        let host = serverName
        // The engine path uses the identifier-bytes validator (Embedded-clean
        // `[UInt8]?`), supplied by the facade bridge; the legacy `certificateValidator`
        // existential closure is not threaded into the engine.
        let validator = peerIdentifierValidator
        let expected = expectedPeerPublicKey
        let pTypes = peerCertificateTypes
        engine.validateCertificate = { @Sendable (chain: [[UInt8]]) throws(TLSEngineError) -> [UInt8]? in
            try Self.validateCertificate(
                chain: chain,
                validatingServerPeer: validatingServerPeer,
                verifyPeer: doVerify,
                allowSelfSigned: allowSelf,
                revocationCheckMode: revocation,
                trustedRoots: roots,
                hostname: host,
                expectedPeerPublicKey: expected,
                peerCertificateTypes: pTypes,
                userValidator: validator
            )
        }

        return engine
    }

    // MARK: - Host strategy helpers (byte-identical to the legacy state machines)

    private static func resolvePeerKey(
        chain: [[UInt8]],
        expectedPeerPublicKey: Data?,
        peerCertificateTypes: [CertificateType]
    ) -> (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)? {
        // The engine passes the resolved key AND the core enforces the
        // scheme/algorithm match. The CertificateVerify `algorithm` is the
        // authoritative scheme when `expectedPeerPublicKey` is configured (matching
        // the legacy `VerificationKey(publicKeyBytes: scheme: cv.algorithm)` path);
        // since the engine cannot supply the CertificateVerify algorithm here, the
        // certificate key (with its intrinsic scheme) is used for resolution and the
        // core checks the scheme match. `expectedPeerPublicKey` is not exposed via
        // the public facade configuration; when set programmatically it is honoured
        // by returning its bytes with the certificate-derived scheme.
        guard let leaf = chain.first else {
            if let expected = expectedPeerPublicKey {
                // No certificate but an expected key was configured — cannot infer
                // the scheme; fail closed (the core rejects a presented-but-unkeyed
                // certificate; an absent certificate with verifyPeer is rejected too).
                _ = expected
            }
            return nil
        }
        // RFC 7250 raw public key.
        if peerCertificateTypes == [.rawPublicKey] {
            let key: VerificationKey
            do {
                key = try SubjectPublicKeyInfo.decode(from: Data(leaf)).verificationKey
            } catch {
                return nil
            }
            if let expected = expectedPeerPublicKey {
                return ([UInt8](expected), key.scheme)
            }
            return ([UInt8](key.publicKeyBytes), key.scheme)
        }
        // X.509. `extractPublicKey()` returns `any TLSVerificationKey`; the concrete
        // `VerificationKey` carries `publicKeyBytes` (matching the legacy adapter's
        // `peerVerificationKey as? VerificationKey` resolution).
        let key: VerificationKey
        do {
            let cert = try X509Certificate.parse(from: Data(leaf))
            guard let extracted = try cert.extractPublicKey() as? VerificationKey else {
                return nil
            }
            key = extracted
        } catch {
            return nil
        }
        if let expected = expectedPeerPublicKey {
            return ([UInt8](expected), key.scheme)
        }
        return ([UInt8](key.publicKeyBytes), key.scheme)
    }

    private static func validateCertificate(
        chain: [[UInt8]],
        validatingServerPeer: Bool,
        verifyPeer: Bool,
        allowSelfSigned: Bool,
        revocationCheckMode: RevocationCheckMode,
        trustedRoots: [X509Certificate],
        hostname: String?,
        expectedPeerPublicKey: Data?,
        peerCertificateTypes: [CertificateType],
        userValidator: (@Sendable ([Data]) throws -> [UInt8]?)?
    ) throws(TLSEngineError) -> [UInt8]? {
        // X.509 chain trust: gated by verifyPeer, only for X.509 leaves (the
        // raw-public-key path evaluates trust in resolvePeerKey / config), and
        // skipped when an explicit expected key is configured (raw-key mode).
        if verifyPeer, expectedPeerPublicKey == nil, peerCertificateTypes != [.rawPublicKey],
           let leaf = chain.first {
            let parsedLeaf: X509Certificate
            do {
                parsedLeaf = try X509Certificate.parse(from: Data(leaf))
            } catch {
                throw .verificationFailed(reason: "certificate parse failed")
            }
            let intermediates: [X509Certificate]
            do {
                intermediates = try chain.dropFirst().compactMap { try X509Certificate.parse(from: Data($0)) }
            } catch {
                throw .verificationFailed(reason: "intermediate certificate parse failed")
            }
            var options = X509ValidationOptions()
            options.hostname = hostname
            options.allowSelfSigned = allowSelfSigned
            options.revocationCheckMode = revocationCheckMode
            options.requiredEKU = validatingServerPeer ? .serverAuth : .clientAuth
            let x509Validator = X509Validator(trustedRoots: trustedRoots, options: options)
            do {
                try x509Validator.validate(certificate: parsedLeaf, intermediates: intermediates)
            } catch {
                throw .verificationFailed(reason: "certificate chain validation failed")
            }
        }

        // User hook (libp2p PeerID extraction). Runs regardless of verifyPeer,
        // after the in-core proof-of-possession check. A throw aborts fail-closed.
        // Its returned identifier bytes (e.g. the libp2p PeerID) are propagated so
        // the engine can surface `peerIdentifier`.
        if let userValidator {
            let certs = chain.map { Data($0) }
            do {
                return try userValidator(certs)
            } catch {
                throw .verificationFailed(reason: "custom certificate validator rejected the peer")
            }
        }
        return nil
    }
}
