/// Embedded-clean configuration for the TLS/DTLS engines.
///
/// This value type carries everything the engine needs to drive the cored
/// handshake FSMs WITHOUT pulling in Foundation, swift-crypto, or X.509. The two
/// genuinely host-coupled responsibilities — CertificateVerify **signing** (a
/// private key, possibly HSM-backed) and **certificate trust evaluation** (X.509
/// chain validation / RFC-7250 raw-public-key matching / the libp2p PeerID
/// extraction hook) — are injected as `@Sendable` closures. The facade fills them:
/// on host with the swift-certificates strategy (`#if canImport(Foundation)`), on
/// Embedded with the `P2PCoreDER` raw-public-key strategy.
///
/// X.509 therefore never enters the engine; the engine only ever sees `[UInt8]`
/// certificate bytes and public-key bytes. The CertificateVerify proof-of-possession
/// signature check stays IN the core (`TLSSignatureVerifier`) — the injected
/// `validateCertificate` closure runs AFTER it (fail-closed: a throw aborts the
/// handshake), exactly as the legacy adapter did.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, no X509, value type.

import TLSWireCore

public struct TLSEngineConfiguration<C>: Sendable where C: Sendable {

    // MARK: - Negotiation (config-dependent, NOT host-coupled)

    /// Server name for SNI (client only).
    public var serverName: String?

    /// ALPN protocols in preference order.
    public var alpnProtocols: [String]

    /// Whether to validate the peer's certificate chain/trust. This gates ONLY the
    /// injected `validateCertificate` strategy — the CertificateVerify
    /// proof-of-possession signature is ALWAYS checked in the core, independent of
    /// this flag (RFC 8446 §4.4.3; the stack-wide S1 invariant).
    public var verifyPeer: Bool

    /// Offered key-exchange groups, in preference order. The first is used for the
    /// initial `key_share`.
    public var supportedGroups: [NamedGroup]

    /// Offered cipher suites, in preference order.
    public var supportedCipherSuites: [CipherSuite]

    /// Signature schemes advertised in `signature_algorithms`. MUST match what the
    /// injected verifier can actually verify (never advertise an unverifiable
    /// capability).
    public var advertisedSignatureSchemes: [SignatureScheme]

    /// RFC 7250 certificate encodings this endpoint presents.
    public var localCertificateTypes: [CertificateType]

    /// RFC 7250 certificate encodings this endpoint accepts from the peer.
    public var peerCertificateTypes: [CertificateType]

    /// Require a client certificate (server only); enables mutual TLS.
    public var requireClientCertificate: Bool

    /// Opaque transport parameters to carry (e.g. for QUIC), or `nil`.
    public var transportParameters: [UInt8]?

    // MARK: - Local identity (injected, host-coupled)

    /// The local certificate chain (DER bytes, leaf first), or `nil`. A server
    /// requires it; a client needs it only for mutual TLS. When `localCertificateTypes`
    /// selects raw public key, this carries the single SubjectPublicKeyInfo DER.
    public var certificateChain: [[UInt8]]?

    /// The local signing key's intrinsic signature scheme (for the CertificateVerify
    /// `algorithm` field), or `nil` when no identity is configured.
    public var signingScheme: SignatureScheme?

    /// Signs `transcriptHash`-derived CertificateVerify content over the local
    /// private key, returning the raw signature bytes (DER for ECDSA in TLS,
    /// raw for Ed25519 — exactly the encoding the wire expects). The closure
    /// receives the FULL signed-content bytes (RFC 8446 §4.4.3 context prefix +
    /// transcript hash) already constructed by the engine. Throwing aborts the
    /// handshake (the facade maps its host signing error to `TLSEngineError`).
    public var sign: (@Sendable (_ signedContent: [UInt8], _ scheme: SignatureScheme) throws(TLSEngineError) -> [UInt8])?

    // MARK: - Peer authentication (injected, host-coupled — X.509 stays OUT)

    /// Resolves the peer's verification public key from its Certificate message.
    /// Receives the peer certificate-list DER bytes (leaf first); returns the
    /// public-key bytes (x963 for NIST curves, raw for Ed25519) plus the key's
    /// intrinsic signature scheme, or `nil` if no usable key could be produced
    /// (the core then fails closed when a certificate was presented).
    ///
    /// Host strategy: parse X.509 leaf / SubjectPublicKeyInfo via swift-certificates.
    /// Embedded strategy: parse the RFC-7250 SubjectPublicKeyInfo DER via `P2PCoreDER`.
    public var resolvePeerKey: (@Sendable (_ certificateListDER: [[UInt8]]) -> (bytes: [UInt8], scheme: SignatureScheme)?)?


    /// Validates the peer's certificate chain/trust AFTER the in-core
    /// CertificateVerify signature check succeeds (the engine emits
    /// `.runCertificateValidator`). Receives the certificate-list DER bytes. A
    /// throw aborts the handshake (fail-closed); returning normally accepts. This
    /// is where the `TLSConfiguration.certificateValidator` user hook (libp2p
    /// PeerID extraction) runs. Only invoked when `verifyPeer` is `true` OR a
    /// certificate was presented (matching the legacy adapter). The facade maps its
    /// host validation error (X.509 / user-hook) to `TLSEngineError` at this boundary.
    ///
    /// Returns the validated peer's application identifier bytes (e.g. the encoded
    /// libp2p PeerID derived from the certificate extension), or `nil` when the
    /// validator established trust without producing an identifier. The engine
    /// records this so the facade can surface `peerIdentity` after the handshake.
    /// Embedded-clean: the identifier is plain `[UInt8]`, never an existential.
    public var validateCertificate: (@Sendable (_ certificateListDER: [[UInt8]]) throws(TLSEngineError) -> [UInt8]?)?

    // MARK: - Initialization

    public init(
        serverName: String? = nil,
        alpnProtocols: [String] = [],
        verifyPeer: Bool = true,
        supportedGroups: [NamedGroup] = [.x25519, .secp256r1, .secp384r1],
        supportedCipherSuites: [CipherSuite] = [
            .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384, .tls_chacha20_poly1305_sha256,
        ],
        advertisedSignatureSchemes: [SignatureScheme] = [
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ed25519,
        ],
        localCertificateTypes: [CertificateType] = [.x509],
        peerCertificateTypes: [CertificateType] = [.x509],
        requireClientCertificate: Bool = false,
        transportParameters: [UInt8]? = nil,
        certificateChain: [[UInt8]]? = nil,
        signingScheme: SignatureScheme? = nil,
        sign: (@Sendable (_ signedContent: [UInt8], _ scheme: SignatureScheme) throws(TLSEngineError) -> [UInt8])? = nil,
        resolvePeerKey: (@Sendable (_ certificateListDER: [[UInt8]]) -> (bytes: [UInt8], scheme: SignatureScheme)?)? = nil,
        validateCertificate: (@Sendable (_ certificateListDER: [[UInt8]]) throws(TLSEngineError) -> [UInt8]?)? = nil
    ) {
        self.serverName = serverName
        self.alpnProtocols = alpnProtocols
        self.verifyPeer = verifyPeer
        self.supportedGroups = supportedGroups
        self.supportedCipherSuites = supportedCipherSuites
        self.advertisedSignatureSchemes = advertisedSignatureSchemes
        self.localCertificateTypes = localCertificateTypes
        self.peerCertificateTypes = peerCertificateTypes
        self.requireClientCertificate = requireClientCertificate
        self.transportParameters = transportParameters
        self.certificateChain = certificateChain
        self.signingScheme = signingScheme
        self.sign = sign
        self.resolvePeerKey = resolvePeerKey
        self.validateCertificate = validateCertificate
    }
}
