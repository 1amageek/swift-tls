/// Shared secret produced by a TLS 1.3 key exchange.
///
/// Wraps the raw shared-secret bytes from either a Diffie-Hellman key
/// agreement or a hybrid KEM exchange. CryptoKit's `SharedSecret` cannot
/// be constructed from raw bytes, so hybrid groups (which concatenate a
/// KEM shared secret with an ECDH shared secret) require this wrapper.

import Foundation
import Crypto

/// The shared secret resulting from key exchange, used as the (EC)DHE
/// input to the TLS 1.3 key schedule.
public struct KeyExchangeSecret: Sendable {

    /// The raw bytes of the shared secret.
    ///
    /// - DH groups (X25519/P-256/P-384): the ECDH output.
    /// - X25519MLKEM768: ML-KEM-768 shared secret (32 bytes) followed by
    ///   the X25519 shared secret (32 bytes), per draft-ietf-tls-ecdhe-mlkem.
    public let rawRepresentation: Data

    /// Creates a secret from raw bytes.
    public init(rawRepresentation: Data) {
        self.rawRepresentation = rawRepresentation
    }

    /// Creates a secret from a CryptoKit DH shared secret.
    public init(_ sharedSecret: SharedSecret) {
        self.rawRepresentation = sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Creates a secret from a CryptoKit symmetric key (KEM output).
    public init(_ symmetricKey: SymmetricKey) {
        self.rawRepresentation = symmetricKey.withUnsafeBytes { Data($0) }
    }
}
