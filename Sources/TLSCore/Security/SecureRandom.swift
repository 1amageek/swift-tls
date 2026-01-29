/// Secure Random Number Generation
///
/// Wraps the system CSPRNG (SecRandomCopyBytes) with error checking.
/// All cryptographic random generation in the project should use this
/// function instead of calling SecRandomCopyBytes directly.

import Foundation
import Security

/// Generate cryptographically secure random bytes.
///
/// - Parameter count: Number of random bytes to generate
/// - Returns: Data containing `count` cryptographically secure random bytes
/// - Throws: If the system CSPRNG fails (e.g., entropy exhaustion)
public func secureRandomBytes(count: Int) throws -> Data {
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { ptr in
        SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
    }
    guard status == errSecSuccess else {
        throw TLSInternalError.randomGenerationFailed(status: status)
    }
    return bytes
}

/// Internal error for secure random generation failure
public enum TLSInternalError: Error, Sendable {
    case randomGenerationFailed(status: OSStatus)
}

extension TLSInternalError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .randomGenerationFailed(let status):
            return "SecRandomCopyBytes failed with status \(status)"
        }
    }
}
