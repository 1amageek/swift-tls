/// Embedded-clean configuration for the DTLS 1.2 engines.
///
/// This value type carries everything the engine needs to drive the cored DTLS
/// handshake FSMs (``DTLSHandshakeCore/DTLSClientHandshake`` /
/// ``DTLSHandshakeCore/DTLSServerHandshake``) WITHOUT pulling in Foundation,
/// swift-crypto, or X.509. The genuinely host-coupled responsibilities — ECDHE key
/// agreement, the ServerKeyExchange / CertificateVerify signing and verification
/// (a private key / X.509 trust), the HelloVerifyRequest cookie HMAC, the CSPRNG
/// randoms, and the cipher-suite selection — are injected as `@Sendable` closures.
/// The facade fills them: on host with the swift-crypto / swift-certificates
/// strategy (`#if canImport(Foundation)`); X.509 therefore never enters the engine.
///
/// All security invariants live where they did before: the cookie binding check is
/// fail-closed (a presented cookie that fails the injected verify is rejected by
/// the core), the ServerKeyExchange and client CertificateVerify signatures are
/// verified by the injected closures and folded into the core fail-closed, and the
/// Finished MAC + anti-replay + epoch monotonicity stay in the cores / engine.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, no X509, value type,
/// typed-throws closures.

import TLSWireCore
import DTLSWireCore

public struct DTLSEngineConfiguration<C>: Sendable where C: Sendable {

    // MARK: - Negotiation (config-dependent)

    /// Cipher suites offered (client) / accepted (server), in preference order.
    public var supportedCipherSuites: [DTLSCipherSuite]

    /// Require the peer to present a certificate AND prove possession of its
    /// private key (mutual authentication). WebRTC / libp2p set this to `true`.
    public var requireClientCertificate: Bool

    // MARK: - Local identity (injected, host-coupled)

    /// The local certificate-list DER bytes (leaf first) for our own Certificate
    /// message. Empty when no identity is configured (a server requires it).
    public var certificateChainDER: [[UInt8]]

    /// The local signing key's intrinsic signature scheme (for the SKE /
    /// CertificateVerify `algorithm` field).
    public var signingScheme: SignatureScheme?

    // MARK: - Host-coupled crypto seams (injected closures)

    /// 32-byte CSPRNG random for our own ClientHello / ServerHello.
    public var randomBytes: (@Sendable (_ count: Int) -> [UInt8])?

    /// Generates an ephemeral ECDHE key pair for `group`, returning our public key
    /// bytes plus an opaque handle the engine passes back to `ecdheAgree`. The
    /// handle is plain `[UInt8]` (the private-key raw representation) so the engine
    /// stays Embedded-clean. Throwing aborts the handshake.
    public var ecdheGenerate: (@Sendable (_ group: NamedGroup) throws(DTLSEngineError) -> (publicKey: [UInt8], privateHandle: [UInt8]))?

    /// Computes the ECDHE shared secret from our `privateHandle` and the peer's
    /// public key. Throwing aborts the handshake.
    public var ecdheAgree: (@Sendable (_ group: NamedGroup, _ privateHandle: [UInt8], _ peerPublicKey: [UInt8]) throws(DTLSEngineError) -> [UInt8])?

    /// Signs `data` with the local private key, returning the raw signature bytes
    /// (DER for ECDSA, raw for Ed25519 — exactly the encoding the DTLS wire
    /// expects). Used for both ServerKeyExchange and CertificateVerify. Throwing
    /// aborts the handshake.
    public var sign: (@Sendable (_ data: [UInt8]) throws(DTLSEngineError) -> [UInt8])?

    /// Verifies a peer signature `signature` over `data` against the peer's
    /// certificate-list DER (X.509 leaf SPKI). Returns `false` on a bad signature;
    /// the core folds the result fail-closed. The injected closure parses the
    /// certificate (X.509 stays OUT of the engine). Throwing aborts the handshake.
    public var verifyPeerSignature: (@Sendable (_ certificateListDER: [[UInt8]], _ signature: [UInt8], _ data: [UInt8]) throws(DTLSEngineError) -> Bool)?

    /// Mints a stateless HelloVerifyRequest cookie (server) over the binding
    /// material the engine constructs (`clientAddress || client_random ||
    /// cipher_suites`). The host computes the HMAC with the rotating cookie secret.
    public var makeCookie: (@Sendable (_ bindingMaterial: [UInt8]) -> [UInt8])?

    /// Verifies a presented cookie (server) against the binding material, returning
    /// `false` on mismatch. The core fails closed on `false` — a presented-but-
    /// unverifiable cookie is always rejected.
    public var verifyCookie: (@Sendable (_ cookie: [UInt8], _ bindingMaterial: [UInt8]) -> Bool)?

    /// Validates the peer's certificate-list DER AFTER the in-core CertificateVerify
    /// proof-of-possession (and, for the server, after the Finished). A throw aborts
    /// the handshake (fail-closed). Returns the validated peer's application
    /// identifier bytes (e.g. an encoded libp2p PeerID) or `nil`. Optional: WebRTC
    /// authenticates by certificate fingerprint at the application layer, so this is
    /// nil there; libp2p supplies it.
    public var validateCertificate: (@Sendable (_ certificateListDER: [[UInt8]]) throws(DTLSEngineError) -> [UInt8]?)?

    // MARK: - Initialization

    public init(
        supportedCipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        requireClientCertificate: Bool = true,
        certificateChainDER: [[UInt8]] = [],
        signingScheme: SignatureScheme? = nil,
        randomBytes: (@Sendable (_ count: Int) -> [UInt8])? = nil,
        ecdheGenerate: (@Sendable (_ group: NamedGroup) throws(DTLSEngineError) -> (publicKey: [UInt8], privateHandle: [UInt8]))? = nil,
        ecdheAgree: (@Sendable (_ group: NamedGroup, _ privateHandle: [UInt8], _ peerPublicKey: [UInt8]) throws(DTLSEngineError) -> [UInt8])? = nil,
        sign: (@Sendable (_ data: [UInt8]) throws(DTLSEngineError) -> [UInt8])? = nil,
        verifyPeerSignature: (@Sendable (_ certificateListDER: [[UInt8]], _ signature: [UInt8], _ data: [UInt8]) throws(DTLSEngineError) -> Bool)? = nil,
        makeCookie: (@Sendable (_ bindingMaterial: [UInt8]) -> [UInt8])? = nil,
        verifyCookie: (@Sendable (_ cookie: [UInt8], _ bindingMaterial: [UInt8]) -> Bool)? = nil,
        validateCertificate: (@Sendable (_ certificateListDER: [[UInt8]]) throws(DTLSEngineError) -> [UInt8]?)? = nil
    ) {
        self.supportedCipherSuites = supportedCipherSuites
        self.requireClientCertificate = requireClientCertificate
        self.certificateChainDER = certificateChainDER
        self.signingScheme = signingScheme
        self.randomBytes = randomBytes
        self.ecdheGenerate = ecdheGenerate
        self.ecdheAgree = ecdheAgree
        self.sign = sign
        self.verifyPeerSignature = verifyPeerSignature
        self.makeCookie = makeCookie
        self.verifyCookie = verifyCookie
        self.validateCertificate = validateCertificate
    }
}
