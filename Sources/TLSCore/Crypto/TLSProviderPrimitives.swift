/// swift-tls's host crypto primitives (swift-crypto / CryptoKit), aggregated by
/// ``TLSProvider``. These were formerly the `TLSFoundation*` types; the duplicate
/// aggregate `TLSFoundationProvider` is deleted and these are renamed `TLS*`.
///
/// The Span->Data bridge is a single bulk copy (`Data(buffer:)`), never the
/// element-wise `for`-append loop that regressed throughput.

import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto

// MARK: - Span -> Data (one bulk copy)

extension Span where Element == UInt8 {
    @inline(__always)
    func tlsPrimData() -> Data {
        let n = count
        guard n > 0 else { return Data() }
        return withUnsafeBufferPointer { source in
            Data(buffer: source)
        }
    }
}

// MARK: - Hashes

public struct TLSSHA256: P2PCoreCrypto.HashFunction {
    public static let digestLength = 32
    public static let blockLength  = 64
    private var hasher = Crypto.SHA256()
    public init() {}
    public mutating func update(_ data: Span<UInt8>) { hasher.update(data: data.tlsPrimData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](hasher.finalize()) }
}

public struct TLSSHA384: P2PCoreCrypto.HashFunction {
    public static let digestLength = 48
    public static let blockLength  = 128
    private var hasher = Crypto.SHA384()
    public init() {}
    public mutating func update(_ data: Span<UInt8>) { hasher.update(data: data.tlsPrimData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](hasher.finalize()) }
}

// MARK: - HKDF

public struct TLSHKDFSHA256: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = TLSSHA256
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = Crypto.HKDF<Crypto.SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.tlsPrimData()), salt: salt.tlsPrimData())
        return prk.withUnsafeBytes { [UInt8]($0) }
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard length <= 255 * Hash.digestLength else {
            throw .invalidLength(expected: 255 * Hash.digestLength, actual: length)
        }
        let okm = Crypto.HKDF<Crypto.SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.tlsPrimData()),
            info: info.tlsPrimData(), outputByteCount: length)
        return okm.withUnsafeBytes { [UInt8]($0) }
    }
}

public struct TLSHKDFSHA384: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = TLSSHA384
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = Crypto.HKDF<Crypto.SHA384>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.tlsPrimData()), salt: salt.tlsPrimData())
        return prk.withUnsafeBytes { [UInt8]($0) }
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard length <= 255 * Hash.digestLength else {
            throw .invalidLength(expected: 255 * Hash.digestLength, actual: length)
        }
        let okm = Crypto.HKDF<Crypto.SHA384>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.tlsPrimData()),
            info: info.tlsPrimData(), outputByteCount: length)
        return okm.withUnsafeBytes { [UInt8]($0) }
    }
}

// MARK: - HMAC

public struct TLSHMACSHA256: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 32
    private var mac: Crypto.HMAC<Crypto.SHA256>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.SHA256>(key: SymmetricKey(data: key.tlsPrimData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.tlsPrimData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.SHA256>.authenticationCode(
            for: message.tlsPrimData(), using: SymmetricKey(data: key.tlsPrimData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.SHA256>.isValidAuthenticationCode(
            mac.tlsPrimData(), authenticating: message.tlsPrimData(),
            using: SymmetricKey(data: key.tlsPrimData()))
    }
}

public struct TLSHMACSHA384: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 48
    private var mac: Crypto.HMAC<Crypto.SHA384>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.SHA384>(key: SymmetricKey(data: key.tlsPrimData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.tlsPrimData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.SHA384>.authenticationCode(
            for: message.tlsPrimData(), using: SymmetricKey(data: key.tlsPrimData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.SHA384>.isValidAuthenticationCode(
            mac.tlsPrimData(), authenticating: message.tlsPrimData(),
            using: SymmetricKey(data: key.tlsPrimData()))
    }
}

public struct TLSHMACSHA1: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 20
    private var mac: Crypto.HMAC<Crypto.Insecure.SHA1>
    public init(key: Span<UInt8>) { mac = Crypto.HMAC<Crypto.Insecure.SHA1>(key: SymmetricKey(data: key.tlsPrimData())) }
    public mutating func update(_ data: Span<UInt8>) { mac.update(data: data.tlsPrimData()) }
    public consuming func finalize() -> [UInt8] { [UInt8](mac.finalize()) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        [UInt8](Crypto.HMAC<Crypto.Insecure.SHA1>.authenticationCode(
            for: message.tlsPrimData(), using: SymmetricKey(data: key.tlsPrimData())))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        Crypto.HMAC<Crypto.Insecure.SHA1>.isValidAuthenticationCode(
            mac.tlsPrimData(), authenticating: message.tlsPrimData(),
            using: SymmetricKey(data: key.tlsPrimData()))
    }
}

// MARK: - Unsupported primitives (not used by the key schedule)

/// The key schedule performs no AEAD; this placeholder throws rather than seal /
/// open with a fabricated result (no silent fallback). TLS record protection uses
/// swift-crypto directly in `TLSRecordCryptor`, not this seam.
public struct TLSUnsupportedAEAD: P2PCoreCrypto.AEAD {
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
public enum TLSHeaderProtection: P2PCoreCrypto.HeaderProtectionProvider {
    public static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
    public static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        throw .unsupportedParameter
    }
}

// MARK: - Random / Clock

public struct TLSRandom: P2PCoreCrypto.RandomSource {
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

public struct TLSClock: P2PCoreCrypto.MonotonicClock {
    public init() {}
    public func monotonicMillis() -> UInt64 { monotonicNanos() / 1_000_000 }
    public func monotonicNanos() -> UInt64 {
        UInt64(DispatchTime.now().uptimeNanoseconds)
    }
}
