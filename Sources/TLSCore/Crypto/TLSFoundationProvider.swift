/// Host (non-Embedded) `CryptoProvider` conformance for the TLSCore adapter.
///
/// `TLSCryptoCore` is generic over `C: CryptoProvider`; the host adapter
/// specialises it at `C = TLSFoundationProvider`, a swift-crypto / CryptoKit
/// backend that is byte-identical to the crypto behavior swift-tls shipped before
/// the seam refactor.
///
/// This provider is TLSCore-internal (it lives in the adapter, never in the
/// Embedded core) because the shared `P2PCryptoFoundation.FoundationCryptoProvider`
/// pulls a vendored swift-crypto whose `.macOS(.v26)` platform floor is
/// incompatible with swift-tls's swift-certificates (`.macOS(.v12)`) graph — the
/// same constraint that forced `QUICFoundationProvider` in swift-quic. The key
/// schedule needs only the hash / HKDF / HMAC primitives; those are implemented
/// faithfully. AEAD, key agreement, signatures, header protection, random, and
/// clock are not used by the key schedule and throw
/// ``P2PCoreCrypto/CryptoError/unsupportedParameter`` rather than fabricate a
/// result (no silent fallback).

import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto

// MARK: - Provider

/// Aggregates swift-crypto–backed hash/HKDF/HMAC behind `P2PCoreCrypto.CryptoProvider`.
public enum TLSFoundationProvider: CryptoProvider {
    public typealias AESGCM128  = TLSFoundationUnsupportedAEAD
    public typealias AESGCM256  = TLSFoundationUnsupportedAEAD
    public typealias ChaChaPoly = TLSFoundationUnsupportedAEAD

    public typealias SHA256 = TLSFoundationSHA256
    public typealias SHA384 = TLSFoundationSHA384

    public typealias HKDFSHA256 = TLSFoundationHKDFSHA256
    public typealias HKDFSHA384 = TLSFoundationHKDFSHA384

    public typealias HMACSHA1   = TLSFoundationHMACSHA1
    public typealias HMACSHA256 = TLSFoundationHMACSHA256
    public typealias HMACSHA384 = TLSFoundationHMACSHA384

    public typealias X25519        = TLSFoundationUnsupportedAgreement
    public typealias P256Agreement = TLSFoundationUnsupportedAgreement
    public typealias P384Agreement = TLSFoundationUnsupportedAgreement

    public typealias Ed25519       = TLSFoundationUnsupportedSignature
    public typealias P256Signature = TLSFoundationUnsupportedSignature
    public typealias P384Signature = TLSFoundationUnsupportedSignature

    public typealias Random           = TLSFoundationRandom
    public typealias Clock            = TLSFoundationClock
    public typealias HeaderProtection = TLSFoundationHeaderProtection

    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> TLSFoundationUnsupportedAEAD {
        throw .unsupportedParameter
    }
    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> TLSFoundationUnsupportedAEAD {
        throw .unsupportedParameter
    }
    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> TLSFoundationUnsupportedAEAD {
        throw .unsupportedParameter
    }

    public static let random = TLSFoundationRandom()
    public static let clock  = TLSFoundationClock()
}

// MARK: - Span <-> bytes helpers (host-only)

extension Span where Element == UInt8 {
    @inline(__always)
    func providerArray() -> [UInt8] {
        var array = [UInt8]()
        array.reserveCapacity(count)
        for index in 0..<count { array.append(self[index]) }
        return array
    }

    @inline(__always)
    func providerData() -> Data { Data(providerArray()) }
}

// MARK: - Hashes

public struct TLSFoundationSHA256: P2PCoreCrypto.HashFunction {
    public static let digestLength = 32
    public static let blockLength  = 64
    private var hasher = Crypto.SHA256()
    public init() {}
    public mutating func update(_ data: Span<UInt8>) { hasher.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](hasher.finalize()) }
}

public struct TLSFoundationSHA384: P2PCoreCrypto.HashFunction {
    public static let digestLength = 48
    public static let blockLength  = 128
    private var hasher = Crypto.SHA384()
    public init() {}
    public mutating func update(_ data: Span<UInt8>) { hasher.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](hasher.finalize()) }
}

// MARK: - HKDF

public struct TLSFoundationHKDFSHA256: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = TLSFoundationSHA256
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = Crypto.HKDF<Crypto.SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.providerData()), salt: salt.providerData())
        return prk.withUnsafeBytes { [UInt8]($0) }
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard length <= 255 * Hash.digestLength else {
            throw .invalidLength(expected: 255 * Hash.digestLength, actual: length)
        }
        let okm = Crypto.HKDF<Crypto.SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.providerData()),
            info: info.providerData(), outputByteCount: length)
        return okm.withUnsafeBytes { [UInt8]($0) }
    }
}

public struct TLSFoundationHKDFSHA384: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = TLSFoundationSHA384
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = Crypto.HKDF<Crypto.SHA384>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.providerData()), salt: salt.providerData())
        return prk.withUnsafeBytes { [UInt8]($0) }
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard length <= 255 * Hash.digestLength else {
            throw .invalidLength(expected: 255 * Hash.digestLength, actual: length)
        }
        let okm = Crypto.HKDF<Crypto.SHA384>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.providerData()),
            info: info.providerData(), outputByteCount: length)
        return okm.withUnsafeBytes { [UInt8]($0) }
    }
}

// MARK: - HMAC

public struct TLSFoundationHMACSHA256: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 32
    private var mac: Crypto.HMAC<Crypto.SHA256>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.SHA256>(key: SymmetricKey(data: key.providerData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.SHA256>.authenticationCode(
            for: message.providerData(), using: SymmetricKey(data: key.providerData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.SHA256>.isValidAuthenticationCode(
            mac.providerData(), authenticating: message.providerData(),
            using: SymmetricKey(data: key.providerData()))
    }
}

public struct TLSFoundationHMACSHA384: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 48
    private var mac: Crypto.HMAC<Crypto.SHA384>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.SHA384>(key: SymmetricKey(data: key.providerData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.SHA384>.authenticationCode(
            for: message.providerData(), using: SymmetricKey(data: key.providerData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.SHA384>.isValidAuthenticationCode(
            mac.providerData(), authenticating: message.providerData(),
            using: SymmetricKey(data: key.providerData()))
    }
}

public struct TLSFoundationHMACSHA1: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 20
    private var mac: Crypto.HMAC<Crypto.Insecure.SHA1>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.Insecure.SHA1>(key: SymmetricKey(data: key.providerData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.providerData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.Insecure.SHA1>.authenticationCode(
            for: message.providerData(), using: SymmetricKey(data: key.providerData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.Insecure.SHA1>.isValidAuthenticationCode(
            mac.providerData(), authenticating: message.providerData(),
            using: SymmetricKey(data: key.providerData()))
    }
}

// MARK: - Unsupported primitives (not used by the key schedule)

/// The key schedule performs no AEAD; this placeholder throws rather than seal /
/// open with a fabricated result (no silent fallback). TLS record protection uses
/// swift-crypto directly in `TLSRecordCryptor`, not this seam.
public struct TLSFoundationUnsupportedAEAD: P2PCoreCrypto.AEAD {
    public static let nonceLength = 12
    public static let tagLength   = 16
    public func seal(_ plaintext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
    public func open(_ ciphertext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
}

/// The key schedule performs no key agreement; this placeholder throws rather
/// than fabricate a key (no silent fallback). TLS key exchange uses swift-crypto
/// directly in `KeyExchange.swift`, not this seam.
public enum TLSFoundationUnsupportedAgreement: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable {}
    public struct PublicKey: Sendable {}
    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey { throw .unsupportedParameter }
    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey { throw .unsupportedParameter }
    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey { throw .unsupportedParameter }
    public static func publicKey(for privateKey: PrivateKey) -> PublicKey { PublicKey() }
    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] { [] }
    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] { [] }
    public static func sharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .keyAgreementFailure
    }
}

/// The key schedule performs no signing; this placeholder throws rather than
/// fabricate a signature (no silent fallback). TLS CertificateVerify uses
/// swift-crypto directly in `Signature.swift`, not this seam.
public enum TLSFoundationUnsupportedSignature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable {}
    public struct VerifyingKey: Sendable {}
    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey { throw .unsupportedParameter }
    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey { throw .unsupportedParameter }
    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey { throw .unsupportedParameter }
    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey { VerifyingKey() }
    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] { [] }
    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] { [] }
    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
    public static func isValid(signature: Span<UInt8>, for message: Span<UInt8>, with verifyingKey: VerifyingKey) -> Bool {
        false
    }
}

/// The key schedule performs no QUIC header protection; this placeholder throws
/// (no silent fallback). Not used by TLS over TCP.
public enum TLSFoundationHeaderProtection: P2PCoreCrypto.HeaderProtectionProvider {
    public static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
    public static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
}

// MARK: - Random / Clock

public struct TLSFoundationRandom: P2PCoreCrypto.RandomSource {
    public init() {}
    public func randomBytes(_ count: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        var out = [UInt8](repeating: 0, count: count)
        for i in 0..<count { out[i] = UInt8.random(in: .min ... .max, using: &rng) }
        return out
    }
    public func fill(_ buffer: inout [UInt8]) {
        var rng = SystemRandomNumberGenerator()
        for i in 0..<buffer.count { buffer[i] = UInt8.random(in: .min ... .max, using: &rng) }
    }
}

public struct TLSFoundationClock: P2PCoreCrypto.MonotonicClock {
    public init() {}
    public func monotonicMillis() -> UInt64 { monotonicNanos() / 1_000_000 }
    public func monotonicNanos() -> UInt64 {
        UInt64(DispatchTime.now().uptimeNanoseconds)
    }
}
