/// Secure Random Number Generation
///
/// Wraps Swift Crypto's secure random key generation.
/// All cryptographic random generation in the project should use this function.

import Crypto
import Foundation

/// Generate cryptographically secure random bytes.
///
/// - Parameter count: Number of random bytes to generate
/// - Returns: Data containing `count` cryptographically secure random bytes
/// - Throws: If the system CSPRNG fails (e.g., entropy exhaustion)
public func secureRandomBytes(count: Int) throws -> Data {
    guard count >= 0 else {
        throw TLSInternalError.invalidByteCount(count)
    }
    guard count <= Int.max / 8 else {
        throw TLSInternalError.invalidByteCount(count)
    }
    guard count > 0 else {
        return Data()
    }

    let key = SymmetricKey(size: SymmetricKeySize(bitCount: count * 8))
    return key.withUnsafeBytes { bytes in
        Data(bytes)
    }
}

/// Internal error for secure random generation failure
public enum TLSInternalError: Error, Sendable {
    case invalidByteCount(Int)
}

extension TLSInternalError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidByteCount(let count):
            return "Invalid secure random byte count: \(count)"
        }
    }
}
