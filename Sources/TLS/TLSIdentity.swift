/// Local authentication material: a signing key plus the certificate chain (or
/// raw public key) presented to the peer.
///
/// Wraps the engine's `SigningKey`/`Certificate` material behind a single facade
/// value. A server always needs an identity; a client needs one only for mutual
/// TLS. The signing-key bytes are the algorithm's raw private-key representation
/// (32-byte scalar for ECDSA P-256 / 48-byte for P-384 / 32-byte seed for
/// Ed25519).
public struct TLSIdentity: Sendable {
    /// The signature scheme of the signing key.
    public enum KeyType: Sendable, Hashable {
        case ecdsaP256
        case ecdsaP384
        case ed25519
    }

    /// The signing key's raw private-key representation.
    public let privateKey: [UInt8]

    /// The signing key's algorithm.
    public let keyType: KeyType

    /// The certificate chain to present (leaf first). For raw-public-key
    /// authentication (RFC 7250) this may be empty and the public key is derived
    /// from the signing key.
    public let certificateChain: [Certificate]

    public init(privateKey: [UInt8], keyType: KeyType, certificateChain: [Certificate]) {
        self.privateKey = privateKey
        self.keyType = keyType
        self.certificateChain = certificateChain
    }
}
