/// TLS 1.2 / DTLS 1.2 PRF (RFC 5246 §5), Embedded-clean.
///
/// ```
/// PRF(secret, label, seed) = P_hash(secret, label + seed)
/// P_hash(secret, seed) = HMAC(secret, A(1) + seed) ||
///                        HMAC(secret, A(2) + seed) || ...
/// A(0) = seed
/// A(i) = HMAC(secret, A(i-1))
/// ```
///
/// Routed through the ``P2PCoreCrypto/MessageAuthenticationCode`` seam
/// (`C.HMACSHA256` / `C.HMACSHA384`) instead of swift-crypto. The hash is selected
/// by a closed switch on ``DTLSWireCore/HashAlgorithm`` so a single value type
/// covers either branch without `any`. Byte-for-byte identical to the swift-crypto
/// path the legacy adapter used.
///
/// Embedded-clean: no Foundation, no `any`, no Mutex, no swift-crypto.

import P2PCoreBytes
import P2PCoreCrypto
import DTLSWireCore

/// The TLS 1.2 / DTLS 1.2 PRF over the crypto MAC seam.
public enum DTLSPRF<C: CryptoProvider> {

    /// Compute `PRF(secret, label, seed)` of `length` bytes for the given hash.
    public static func compute(
        secret: [UInt8],
        label: String,
        seed: [UInt8],
        length: Int,
        hash: HashAlgorithm
    ) -> [UInt8] {
        var combined = [UInt8]()
        combined.reserveCapacity(label.utf8.count + seed.count)
        combined.append(contentsOf: Array(label.utf8))
        combined.append(contentsOf: seed)
        switch hash {
        case .sha256:
            return pHash256(secret: secret, seed: combined, length: length)
        case .sha384:
            return pHash384(secret: secret, seed: combined, length: length)
        }
    }

    // MARK: - P_hash expansions

    private static func pHash256(secret: [UInt8], seed: [UInt8], length: Int) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(length)

        // A(0) = seed
        var a = seed
        while result.count < length {
            // A(i) = HMAC(secret, A(i-1))
            a = C.HMACSHA256.authenticationCode(for: a.span, key: secret.span)
            // block = HMAC(secret, A(i) + seed)
            var input = [UInt8]()
            input.reserveCapacity(a.count + seed.count)
            input.append(contentsOf: a)
            input.append(contentsOf: seed)
            let block = C.HMACSHA256.authenticationCode(for: input.span, key: secret.span)
            result.append(contentsOf: block)
        }
        if result.count > length {
            result.removeLast(result.count - length)
        }
        return result
    }

    private static func pHash384(secret: [UInt8], seed: [UInt8], length: Int) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(length)

        var a = seed
        while result.count < length {
            a = C.HMACSHA384.authenticationCode(for: a.span, key: secret.span)
            var input = [UInt8]()
            input.reserveCapacity(a.count + seed.count)
            input.append(contentsOf: a)
            input.append(contentsOf: seed)
            let block = C.HMACSHA384.authenticationCode(for: input.span, key: secret.span)
            result.append(contentsOf: block)
        }
        if result.count > length {
            result.removeLast(result.count - length)
        }
        return result
    }
}
