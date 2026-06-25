/// The HOST ECDHE + X.509 + cookie strategy for the cored ``DTLSEngineCore`` engines.
///
/// Builds a `DTLSEngineCore.DTLSEngineConfiguration<TLSCryptoProvider>` from a
/// `DTLSCertificate` + the `requireClientCertificate` policy, filling the engine's
/// injected seams with the swift-crypto / swift-certificates host strategy:
///
/// - `randomBytes`          — the system CSPRNG (ClientHello / ServerHello randoms).
/// - `ecdheGenerate`        — `KeyExchange.generate(for:)` (P-256), returning our
///   public key + the raw private-key bytes as an opaque handle.
/// - `ecdheAgree`           — reconstructs the `KeyExchange` from the handle and runs
///   `sharedSecret(with:)` — byte-identical to the legacy handler.
/// - `sign`                 — the certificate's `SigningKey.sign` (ECDSA-DER over the
///   ServerKeyExchange params / the CertificateVerify transcript hash).
/// - `verifyPeerSignature`  — `VerificationKey(certificateData:)` + `verify(_:for:)`
///   over the peer's certificate (ServerKeyExchange / CertificateVerify).
/// - `makeCookie`/`verifyCookie` — the rotating `DTLSCookieSecretProvider` HMAC.
/// - `validateCertificate`  — optional (nil here): WebRTC authenticates by certificate
///   fingerprint at the application layer; libp2p supplies its own validator.
///
/// X.509 / swift-crypto are structurally Foundation-bound, so this lives only on the
/// host (DTLSCore is the host adapter). The Embedded build supplies its own seam set.
///
/// Security: the cookie binding (fail-closed), the ServerKeyExchange / client
/// CertificateVerify proof-of-possession, and the certificate surfacing are
/// preserved unchanged; no failure is silently swallowed.

import Foundation
import Crypto
import P2PCoreBytes
import TLSWireCore
import TLSCryptoCore
import TLSCore
import DTLSWireCore
import DTLSEngineCore

extension DTLSCertificate {

    /// Builds the cored DTLS engine configuration from this identity.
    ///
    /// - Parameters:
    ///   - requireClientCertificate: server-side mutual-auth policy.
    ///   - cookieProvider: the rotating cookie-secret provider (server only).
    ///   - supportedCipherSuites: offered/accepted suites.
    public func makeDTLSEngineConfiguration(
        requireClientCertificate: Bool,
        cookieProvider: DTLSCookieSecretProvider = .shared,
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256]
    ) -> DTLSEngineConfiguration<TLSCryptoProvider> {
        let signer = self.signingKey
        let chainDER: [[UInt8]] = [[UInt8](self.derEncoded)]

        var engine = DTLSEngineConfiguration<TLSCryptoProvider>(
            supportedCipherSuites: supportedCipherSuites,
            requireClientCertificate: requireClientCertificate,
            certificateChainDER: chainDER,
            signingScheme: signer.scheme
        )

        // CSPRNG randoms. `SymmetricKey(size:)` draws from the system CSPRNG and does
        // not throw, so no throwing RNG API (and no `try!`) is involved.
        engine.randomBytes = { @Sendable (count: Int) -> [UInt8] in
            Self.randomBytes(count)
        }

        // ECDHE key generation: returns our public key + the raw private-key handle.
        // Uses the Embedded-clean `TLSKeyExchange` seam (byte-identical to the host
        // `KeyExchange` enum: P-256 x963 public key, raw private key).
        engine.ecdheGenerate = { @Sendable (group: NamedGroup) throws(DTLSEngineError) -> (publicKey: [UInt8], privateHandle: [UInt8]) in
            do {
                let pair = try TLSKeyExchange<TLSCryptoProvider>.generate(for: group)
                return (publicKey: pair.publicKeyBytes, privateHandle: pair.privateKeyBytes)
            } catch {
                throw .protocolFailure(reason: "DTLS ECDHE key generation failed")
            }
        }

        // ECDHE agreement: recompute the shared secret from the handle + peer key.
        engine.ecdheAgree = { @Sendable (group: NamedGroup, handle: [UInt8], peerPublicKey: [UInt8]) throws(DTLSEngineError) -> [UInt8] in
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

        // Sign with our private key (ServerKeyExchange params / CertificateVerify hash).
        engine.sign = { @Sendable (data: [UInt8]) throws(DTLSEngineError) -> [UInt8] in
            do {
                return [UInt8](try signer.sign(Data(data)))
            } catch {
                throw .verificationFailed(reason: "DTLS signing failed")
            }
        }

        // Verify a peer signature against the peer's certificate (X.509).
        engine.verifyPeerSignature = { @Sendable (chain: [[UInt8]], signature: [UInt8], data: [UInt8]) throws(DTLSEngineError) -> Bool in
            guard let leaf = chain.first else { return false }
            do {
                let key = try VerificationKey(certificateData: Data(leaf))
                return try key.verify(signature: Data(signature), for: Data(data))
            } catch {
                throw .verificationFailed(reason: "DTLS peer signature verification failed")
            }
        }

        // Cookie HMAC (server). Bound to the engine-constructed binding material.
        engine.makeCookie = { @Sendable (material: [UInt8]) -> [UInt8] in
            [UInt8](cookieProvider.makeCookie(bindingMaterial: Data(material)))
        }
        engine.verifyCookie = { @Sendable (cookie: [UInt8], material: [UInt8]) -> Bool in
            cookieProvider.verifyCookie(Data(cookie), bindingMaterial: Data(material))
        }

        return engine
    }

    /// System-CSPRNG bytes (non-throwing, via `SymmetricKey`'s CSPRNG-backed init).
    static func randomBytes(_ count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        var out = [UInt8]()
        out.reserveCapacity(count)
        // Draw 256-bit blocks from the system CSPRNG until `count` is satisfied.
        while out.count < count {
            let block = SymmetricKey(size: .bits256).withUnsafeBytes { [UInt8]($0) }
            out.append(contentsOf: block)
        }
        return Array(out.prefix(count))
    }
}
