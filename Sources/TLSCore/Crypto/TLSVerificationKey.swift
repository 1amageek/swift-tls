/// TLS Verification Key Protocol
///
/// Defines a protocol for verification keys used in TLS handshake (CertificateVerify).
/// The default implementations cover ECDSA (P-256, P-384) and Ed25519.
/// Consumers can provide custom implementations for RSA or post-quantum keys.

import Foundation

/// Protocol for verification keys used in TLS CertificateVerify.
///
/// Adopt this protocol to provide custom key types (e.g., RSA, HSM-backed keys,
/// or post-quantum algorithms) while remaining compatible with the TLS handshake.
public protocol TLSVerificationKey: Sendable {
    /// The signature scheme associated with this key
    var scheme: SignatureScheme { get }

    /// Verify a signature against the given data
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The signed data
    /// - Returns: `true` if the signature is valid
    func verify(signature: Data, for data: Data) throws -> Bool
}
