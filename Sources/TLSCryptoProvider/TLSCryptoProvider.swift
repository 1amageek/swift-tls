/// The TLS crypto provider — the unified ``P2PCrypto/DefaultCryptoProvider`` for
/// every primitive except the two ECDSA signature schemes.
///
/// embedded-first-api.md §2.2 unifies the per-library `*FoundationProvider`s into a
/// single shared ``DefaultCryptoProvider``. swift-tls adopts it wholesale for AEAD,
/// hashing, HKDF, HMAC, header protection, key agreement, Ed25519 signing, entropy
/// and the monotonic clock — bringing the shared provider's bulk-copy primitives.
/// This is UNIFORM with swift-quic's `QUICCryptoProvider`.
///
/// The ONE exception is ECDSA: the shared provider emits ECDSA signatures in *raw*
/// `r || s` form (correct for Noise/libp2p), whereas the TLS 1.3 CertificateVerify
/// wire format (RFC 8446 §4.2.3) requires *DER*. Emitting raw ECDSA on the TLS wire
/// would silently break interop and is caught by the signature seam differential
/// tests. This composite therefore overrides `P256Signature`/`P384Signature` with
/// the DER schemes and inherits everything else from the shared provider —
/// preserving the CertificateVerify bytes byte-identically while still unifying the
/// rest of the crypto surface.
///
/// The DER-ECDSA override is dual-built:
///   - host (`#else`): ``TLSDERP256Signature`` / ``TLSDERP384Signature`` over
///     swift-crypto's `derRepresentation`.
///   - Embedded (`#if hasFeature(Embedded)`): ``EmbeddedDERP256Signature`` /
///     ``EmbeddedDERP384Signature`` over the BoringSSL raw `r || s` schemes, with a
///     `P2PCoreDER` DER wrapper that is byte-identical to the host output.
///
/// This target is the SINGLE place in swift-tls that imports `P2PCrypto`; it is the
/// one provider type the swift-tls cores specialise at.

import P2PCrypto
import P2PCoreCrypto
/// The crypto provider the swift-tls cores specialise at. Identical to
/// ``DefaultCryptoProvider`` except ECDSA signatures are DER-encoded for the TLS
/// CertificateVerify wire (RFC 8446 §4.2.3).
public enum TLSCryptoProvider: CryptoProvider {
    // AEAD — inherited from the shared provider.
    public typealias AESGCM128  = DefaultCryptoProvider.AESGCM128
    public typealias AESGCM256  = DefaultCryptoProvider.AESGCM256
    public typealias ChaChaPoly = DefaultCryptoProvider.ChaChaPoly

    // Hashes — inherited.
    public typealias SHA256 = DefaultCryptoProvider.SHA256
    public typealias SHA384 = DefaultCryptoProvider.SHA384

    // Key derivation — inherited (hash-bound by the same SHA256/SHA384).
    public typealias HKDFSHA256 = DefaultCryptoProvider.HKDFSHA256
    public typealias HKDFSHA384 = DefaultCryptoProvider.HKDFSHA384

    // Message authentication — inherited.
    public typealias HMACSHA1   = DefaultCryptoProvider.HMACSHA1
    public typealias HMACSHA256 = DefaultCryptoProvider.HMACSHA256
    public typealias HMACSHA384 = DefaultCryptoProvider.HMACSHA384

    // Key agreement — inherited (shared secrets are raw bytes, format-identical).
    public typealias X25519        = DefaultCryptoProvider.X25519
    public typealias P256Agreement = DefaultCryptoProvider.P256Agreement
    public typealias P384Agreement = DefaultCryptoProvider.P384Agreement

    // Signatures — Ed25519 inherited (raw 64-byte, identical wire form);
    // ECDSA OVERRIDDEN to DER for the TLS CertificateVerify wire (RFC 8446 §4.2.3).
    public typealias Ed25519       = DefaultCryptoProvider.Ed25519
    #if hasFeature(Embedded)
    public typealias P256Signature = EmbeddedDERP256Signature
    public typealias P384Signature = EmbeddedDERP384Signature
    #else
    public typealias P256Signature = TLSDERP256Signature
    public typealias P384Signature = TLSDERP384Signature
    #endif

    // Ambient capabilities — inherited.
    public typealias Random           = DefaultCryptoProvider.Random
    public typealias Clock            = DefaultCryptoProvider.Clock
    public typealias HeaderProtection = DefaultCryptoProvider.HeaderProtection

    // AEAD factories — forward to the shared provider. Fully-qualify the thrown
    // error so the unqualified name cannot shadow `P2PCoreCrypto.CryptoError`.
    @inline(__always)
    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> AESGCM128 {
        try DefaultCryptoProvider.makeAESGCM128(key: key)
    }
    @inline(__always)
    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> AESGCM256 {
        try DefaultCryptoProvider.makeAESGCM256(key: key)
    }
    @inline(__always)
    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> ChaChaPoly {
        try DefaultCryptoProvider.makeChaChaPoly(key: key)
    }

    // Ambient singletons — forward to the shared provider.
    public static var random: Random { DefaultCryptoProvider.random }
    public static var clock:  Clock  { DefaultCryptoProvider.clock }
}
