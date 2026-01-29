/// Constant-Time Comparison
///
/// Prevents timing side-channel attacks by ensuring comparison time
/// is proportional to the data length, regardless of where differences occur.
///
/// Used for verify_data (Finished messages), HMAC tags, and cookie verification.

import Foundation

/// Compare two Data values in constant time.
///
/// Returns `true` if and only if both sequences have equal length and
/// identical byte contents. The comparison always examines every byte,
/// preventing timing side-channel leaks.
///
/// - Parameters:
///   - a: First data to compare
///   - b: Second data to compare
/// - Returns: `true` if the sequences are identical
public func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var result: UInt8 = 0
    for i in 0..<a.count {
        result |= a[a.startIndex + i] ^ b[b.startIndex + i]
    }
    return result == 0
}
