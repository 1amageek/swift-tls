// swift-tls's concrete crypto backend.
//
// The session package does not maintain a second primitive implementation.
// `P2PCrypto.DefaultCryptoProvider` is the single adapter over
// swift-ssl/SSLCrypto, including the P-384 ECDH and ECDSA paths.

import P2PCrypto
import P2PCoreCrypto

public enum TLSCryptoProvider: CryptoProvider {
    public typealias AESGCM128 = DefaultCryptoProvider.AESGCM128
    public typealias AESGCM256 = DefaultCryptoProvider.AESGCM256
    public typealias ChaChaPoly = DefaultCryptoProvider.ChaChaPoly
    public typealias SHA256 = DefaultCryptoProvider.SHA256
    public typealias SHA384 = DefaultCryptoProvider.SHA384
    public typealias HKDFSHA256 = DefaultCryptoProvider.HKDFSHA256
    public typealias HKDFSHA384 = DefaultCryptoProvider.HKDFSHA384
    public typealias HMACSHA1 = DefaultCryptoProvider.HMACSHA1
    public typealias HMACSHA256 = DefaultCryptoProvider.HMACSHA256
    public typealias HMACSHA384 = DefaultCryptoProvider.HMACSHA384
    public typealias X25519 = DefaultCryptoProvider.X25519
    public typealias P256Agreement = DefaultCryptoProvider.P256Agreement
    public typealias P384Agreement = DefaultCryptoProvider.P384Agreement
    public typealias Ed25519 = DefaultCryptoProvider.Ed25519
    public typealias P256Signature = DefaultCryptoProvider.P256Signature
    public typealias P384Signature = DefaultCryptoProvider.P384Signature
    public typealias RawP256Signature = DefaultCryptoProvider.RawP256Signature
    public typealias RawP384Signature = DefaultCryptoProvider.RawP384Signature
    public typealias Random = DefaultCryptoProvider.Random
    public typealias Clock = DefaultCryptoProvider.Clock
    public typealias HeaderProtection = DefaultCryptoProvider.HeaderProtection

    public static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> AESGCM128 {
        try DefaultCryptoProvider.makeAESGCM128(key: key)
    }

    public static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> AESGCM256 {
        try DefaultCryptoProvider.makeAESGCM256(key: key)
    }

    public static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> ChaChaPoly {
        try DefaultCryptoProvider.makeChaChaPoly(key: key)
    }

    public static let random = DefaultCryptoProvider.random
    public static let clock = DefaultCryptoProvider.clock
}
