/// TLS 1.2 PRF (Pseudo-Random Function) with SHA-256
///
/// RFC 5246 Section 5:
///   PRF(secret, label, seed) = P_SHA256(secret, label + seed)
///   P_hash(secret, seed) = HMAC(secret, A(1) + seed) ||
///                          HMAC(secret, A(2) + seed) || ...
///   A(0) = seed
///   A(i) = HMAC(secret, A(i-1))

import Foundation
import Crypto

/// TLS 1.2 Pseudo-Random Function
public enum PRF: Sendable {

    /// Compute PRF with SHA-256
    /// - Parameters:
    ///   - secret: The secret key
    ///   - label: ASCII label string
    ///   - seed: The seed data
    ///   - length: Desired output length in bytes
    /// - Returns: Derived key material
    public static func compute(
        secret: Data,
        label: String,
        seed: Data,
        length: Int
    ) -> Data {
        let labelData = Data(label.utf8)
        let combinedSeed = labelData + seed
        return pHash(secret: secret, seed: combinedSeed, length: length)
    }

    /// P_SHA256 expansion function
    private static func pHash(secret: Data, seed: Data, length: Int) -> Data {
        let key = SymmetricKey(data: secret)
        var result = Data()
        result.reserveCapacity(length)

        // A(0) = seed
        var a = seed

        while result.count < length {
            // A(i) = HMAC(secret, A(i-1))
            a = Data(HMAC<SHA256>.authenticationCode(for: a, using: key))
            // P_hash output block = HMAC(secret, A(i) + seed)
            let block = Data(HMAC<SHA256>.authenticationCode(for: a + seed, using: key))
            result.append(block)
        }

        return Data(result.prefix(length))
    }

    /// Compute PRF with SHA-384 (for AES-256-GCM suites)
    public static func computeSHA384(
        secret: Data,
        label: String,
        seed: Data,
        length: Int
    ) -> Data {
        let labelData = Data(label.utf8)
        let combinedSeed = labelData + seed
        return pHashSHA384(secret: secret, seed: combinedSeed, length: length)
    }

    /// P_SHA384 expansion function
    private static func pHashSHA384(secret: Data, seed: Data, length: Int) -> Data {
        let key = SymmetricKey(data: secret)
        var result = Data()
        result.reserveCapacity(length)

        var a = seed

        while result.count < length {
            a = Data(HMAC<SHA384>.authenticationCode(for: a, using: key))
            let block = Data(HMAC<SHA384>.authenticationCode(for: a + seed, using: key))
            result.append(block)
        }

        return Data(result.prefix(length))
    }
}
