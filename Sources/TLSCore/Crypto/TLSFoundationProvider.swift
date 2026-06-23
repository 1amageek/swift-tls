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
/// same constraint that forced `QUICFoundationProvider` in swift-quic. The hash /
/// HKDF / HMAC primitives back the key schedule; the X25519 / P-256 / P-384 key
/// agreement and Ed25519 / ECDSA-P256 / ECDSA-P384 signature schemes back
/// `TLSKeyExchange` and `TLSSignature{Signer,Verifier}` — all implemented
/// faithfully and byte-identically to the legacy direct-swift-crypto paths
/// (`KeyExchange.swift`, `Signature.swift`). ECDSA signatures use the DER
/// encoding the TLS wire format requires, matching the legacy CertificateVerify
/// bytes exactly. AEAD, header protection, random, and clock are not used by these
/// seam paths; AEAD/header-protection throw
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

    public typealias X25519        = TLSFoundationX25519
    public typealias P256Agreement = TLSFoundationP256Agreement
    public typealias P384Agreement = TLSFoundationP384Agreement

    public typealias Ed25519       = TLSFoundationEd25519
    public typealias P256Signature = TLSFoundationP256Signature
    public typealias P384Signature = TLSFoundationP384Signature

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
