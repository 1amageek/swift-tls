/// TLS Signing Key Protocol
///
/// Defines a protocol for signing keys used in TLS handshake (CertificateVerify).
/// The default implementations cover ECDSA (P-256, P-384) and Ed25519.
/// Consumers can provide custom implementations for RSA, HSM, or post-quantum keys.

import Foundation

/// Protocol for signing keys used in TLS CertificateVerify.
///
/// Adopt this protocol to provide custom key types (e.g., RSA, HSM-backed keys,
/// or post-quantum algorithms) while remaining compatible with the TLS handshake.
public protocol TLSSigningKey: Sendable {
    /// The signature scheme associated with this key
    var scheme: SignatureScheme { get }

    /// The public key bytes (format depends on key type)
    var publicKeyBytes: Data { get }

    /// Sign the given data
    /// - Parameter data: The data to sign
    /// - Returns: The signature
    func sign(_ data: Data) throws -> Data
}
