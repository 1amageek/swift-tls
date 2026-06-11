/// TLS 1.3 Key Exchange (RFC 8446 Section 4.2.8)
///
/// Supports X25519, P-256 (secp256r1), P-384 (secp384r1), and the
/// post-quantum hybrid X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem).

import Foundation
import Crypto

// MARK: - Hybrid Group Constants

/// Wire-format sizes for X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem)
///
/// Client share: ML-KEM-768 encapsulation key (1184) || X25519 public key (32)
/// Server share: ML-KEM-768 ciphertext (1088) || X25519 public key (32)
/// Shared secret: ML-KEM-768 shared secret (32) || X25519 shared secret (32)
///
/// Note: the ML-KEM component comes FIRST, unlike the obsolete
/// X25519Kyber768Draft00 codepoint which placed X25519 first.
enum X25519MLKEM768Sizes {
    static let mlkemEncapsulationKey = 1184
    static let mlkemCiphertext = 1088
    static let x25519PublicKey = 32
    static let clientShare = mlkemEncapsulationKey + x25519PublicKey  // 1216
    static let serverShare = mlkemCiphertext + x25519PublicKey        // 1120
}

// MARK: - Key Exchange

/// Key exchange abstraction for TLS 1.3
public enum KeyExchange: Sendable {
    case x25519(Curve25519.KeyAgreement.PrivateKey)
    case p256(P256.KeyAgreement.PrivateKey)
    case p384(P384.KeyAgreement.PrivateKey)

    /// Hybrid post-quantum key exchange (client role).
    ///
    /// The client generates both key pairs and sends
    /// `mlkem_encapsulation_key || x25519_public_key` as its share.
    /// The server responds via ``respond(group:peerShare:)`` because a KEM
    /// requires encapsulation against the client's key rather than an
    /// independent key generation.
    ///
    /// The ML-KEM private key is stored as its seed representation because
    /// swift-crypto's `MLKEM768.PrivateKey` is not `Sendable` on Linux and
    /// therefore cannot be an associated value of this `Sendable` enum.
    /// The key is reconstructed from the seed at decapsulation time.
    case x25519MLKEM768(
        mlkemSeed: Data,
        mlkemEncapsulationKey: Data,
        x25519: Curve25519.KeyAgreement.PrivateKey
    )

    // MARK: - Generation

    /// Generate a new key pair for the specified named group
    /// - Parameter group: The named group (curve)
    /// - Returns: A new key exchange instance
    public static func generate(for group: NamedGroup) throws -> KeyExchange {
        switch group {
        case .x25519:
            return .x25519(Curve25519.KeyAgreement.PrivateKey())
        case .secp256r1:
            return .p256(P256.KeyAgreement.PrivateKey())
        case .secp384r1:
            return .p384(P384.KeyAgreement.PrivateKey())
        case .x25519MLKEM768:
            let mlkemKey = try MLKEM768.PrivateKey.generate()
            return .x25519MLKEM768(
                mlkemSeed: mlkemKey.seedRepresentation,
                mlkemEncapsulationKey: mlkemKey.publicKey.rawRepresentation,
                x25519: Curve25519.KeyAgreement.PrivateKey()
            )
        default:
            throw KeyExchangeError.unsupportedGroup(group)
        }
    }

    // MARK: - Properties

    /// The named group for this key exchange
    public var group: NamedGroup {
        switch self {
        case .x25519: return .x25519
        case .p256: return .secp256r1
        case .p384: return .secp384r1
        case .x25519MLKEM768: return .x25519MLKEM768
        }
    }

    /// The public key bytes (for key_share extension)
    ///
    /// - X25519: 32 bytes (raw representation)
    /// - P-256: 65 bytes (uncompressed point, 0x04 || x || y)
    /// - P-384: 97 bytes (uncompressed point, 0x04 || x || y)
    /// - X25519MLKEM768: 1216 bytes (ML-KEM-768 encapsulation key || X25519 public key)
    public var publicKeyBytes: Data {
        switch self {
        case .x25519(let privateKey):
            return Data(privateKey.publicKey.rawRepresentation)
        case .p256(let privateKey):
            return Data(privateKey.publicKey.x963Representation)
        case .p384(let privateKey):
            return Data(privateKey.publicKey.x963Representation)
        case .x25519MLKEM768(_, let mlkemEncapsulationKey, let x25519):
            var bytes = mlkemEncapsulationKey
            bytes.append(Data(x25519.publicKey.rawRepresentation))
            return bytes
        }
    }

    // MARK: - Key Agreement

    /// Perform key agreement with the peer's key share.
    ///
    /// For DH groups, the peer share is the peer's public key and this
    /// works symmetrically for both roles. For X25519MLKEM768, this is the
    /// CLIENT-side operation: the peer share is the server's response
    /// (`mlkem_ciphertext || x25519_public_key`) and the ML-KEM component
    /// is decapsulated with our private key.
    ///
    /// - Parameter peerPublicKeyBytes: The peer's key share bytes
    /// - Returns: The shared secret
    public func sharedSecret(with peerPublicKeyBytes: Data) throws -> KeyExchangeSecret {
        switch self {
        case .x25519(let privateKey):
            guard peerPublicKeyBytes.count == 32 else {
                throw KeyExchangeError.invalidPublicKey("X25519 public key must be 32 bytes")
            }
            let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: peerPublicKeyBytes
            )
            return KeyExchangeSecret(try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey))

        case .p256(let privateKey):
            // P-256 uses x963 representation (uncompressed point)
            let peerPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: peerPublicKeyBytes
            )
            return KeyExchangeSecret(try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey))

        case .p384(let privateKey):
            // P-384 uses x963 representation (uncompressed point)
            let peerPublicKey = try P384.KeyAgreement.PublicKey(
                x963Representation: peerPublicKeyBytes
            )
            return KeyExchangeSecret(try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey))

        case .x25519MLKEM768(let mlkemSeed, _, let x25519):
            guard peerPublicKeyBytes.count == X25519MLKEM768Sizes.serverShare else {
                throw KeyExchangeError.invalidPublicKey(
                    "X25519MLKEM768 server share must be \(X25519MLKEM768Sizes.serverShare) bytes, got \(peerPublicKeyBytes.count)"
                )
            }
            let ciphertextEnd = peerPublicKeyBytes.startIndex + X25519MLKEM768Sizes.mlkemCiphertext
            let ciphertext = peerPublicKeyBytes[peerPublicKeyBytes.startIndex..<ciphertextEnd]
            let peerX25519Bytes = peerPublicKeyBytes[ciphertextEnd...]

            let mlkemKey = try MLKEM768.PrivateKey(seedRepresentation: mlkemSeed, publicKey: nil)
            let mlkemSecret = try mlkemKey.decapsulate(ciphertext)

            let peerX25519Key = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: peerX25519Bytes
            )
            let x25519Secret = try x25519.sharedSecretFromKeyAgreement(with: peerX25519Key)

            // ML-KEM shared secret first, then X25519 (draft-ietf-tls-ecdhe-mlkem)
            var combined = mlkemSecret.withUnsafeBytes { Data($0) }
            combined.append(x25519Secret.withUnsafeBytes { Data($0) })
            return KeyExchangeSecret(rawRepresentation: combined)
        }
    }

    // MARK: - Server Response

    /// Compute the server's key share and shared secret from a client share.
    ///
    /// This is the SERVER-side operation. For DH groups it generates an
    /// ephemeral key pair and performs key agreement. For X25519MLKEM768 it
    /// encapsulates against the client's ML-KEM encapsulation key (producing
    /// a ciphertext that depends on the client share) and performs X25519
    /// key agreement with a fresh ephemeral key.
    ///
    /// - Parameters:
    ///   - group: The negotiated named group
    ///   - peerShare: The client's key_share bytes
    /// - Returns: The server's key share bytes and the shared secret
    public static func respond(
        group: NamedGroup,
        peerShare: Data
    ) throws -> (ourShare: Data, secret: KeyExchangeSecret) {
        switch group {
        case .x25519, .secp256r1, .secp384r1:
            let keyExchange = try generate(for: group)
            let secret = try keyExchange.sharedSecret(with: peerShare)
            return (keyExchange.publicKeyBytes, secret)

        case .x25519MLKEM768:
            guard peerShare.count == X25519MLKEM768Sizes.clientShare else {
                throw KeyExchangeError.invalidPublicKey(
                    "X25519MLKEM768 client share must be \(X25519MLKEM768Sizes.clientShare) bytes, got \(peerShare.count)"
                )
            }
            let encapKeyEnd = peerShare.startIndex + X25519MLKEM768Sizes.mlkemEncapsulationKey
            let encapsulationKeyBytes = peerShare[peerShare.startIndex..<encapKeyEnd]
            let peerX25519Bytes = peerShare[encapKeyEnd...]

            let mlkemPublicKey: MLKEM768.PublicKey
            do {
                mlkemPublicKey = try MLKEM768.PublicKey(rawRepresentation: encapsulationKeyBytes)
            } catch {
                throw KeyExchangeError.invalidPublicKey(
                    "Invalid ML-KEM-768 encapsulation key: \(error)"
                )
            }
            // CryptoKit defers part of the FIPS 203 encapsulation key checks
            // to encapsulation time, so a key that passed the initializer can
            // still fail here. Either way the peer sent an invalid key.
            let mlkemCiphertext: Data
            let mlkemSharedSecret: Data
            do {
                let encapsulation = try mlkemPublicKey.encapsulate()
                mlkemCiphertext = encapsulation.encapsulated
                mlkemSharedSecret = encapsulation.sharedSecret.withUnsafeBytes { Data($0) }
            } catch {
                throw KeyExchangeError.invalidPublicKey(
                    "ML-KEM-768 encapsulation failed: \(error)"
                )
            }

            let x25519Key = Curve25519.KeyAgreement.PrivateKey()
            let peerX25519Key = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: peerX25519Bytes
            )
            let x25519Secret = try x25519Key.sharedSecretFromKeyAgreement(with: peerX25519Key)

            // Server share: ML-KEM ciphertext first, then X25519 public key
            var ourShare = mlkemCiphertext
            ourShare.append(Data(x25519Key.publicKey.rawRepresentation))

            // Shared secret: ML-KEM shared secret first, then X25519
            var combined = mlkemSharedSecret
            combined.append(x25519Secret.withUnsafeBytes { Data($0) })

            return (ourShare, KeyExchangeSecret(rawRepresentation: combined))

        default:
            throw KeyExchangeError.unsupportedGroup(group)
        }
    }

    // MARK: - Key Share Entry

    /// Create a KeyShareEntry for this key exchange
    public func keyShareEntry() -> KeyShareEntry {
        KeyShareEntry(group: group, keyExchange: publicKeyBytes)
    }
}

// MARK: - Static Key Agreement

extension KeyExchange {
    /// Perform key agreement given a named group and peer public key
    /// - Parameters:
    ///   - group: The named group
    ///   - peerPublicKeyBytes: The peer's public key bytes
    /// - Returns: Tuple of (sharedSecret, ourPublicKeyBytes)
    public static func performKeyAgreement(
        group: NamedGroup,
        peerPublicKeyBytes: Data
    ) throws -> (sharedSecret: KeyExchangeSecret, ourPublicKeyBytes: Data) {
        let (ourShare, secret) = try respond(group: group, peerShare: peerPublicKeyBytes)
        return (secret, ourShare)
    }
}

// MARK: - Key Exchange Errors

/// Errors during key exchange
public enum KeyExchangeError: Error, Sendable {
    case unsupportedGroup(NamedGroup)
    case invalidPublicKey(String)
    case keyAgreementFailed(String)
}

// MARK: - Shared Secret Extension

extension SharedSecret {
    /// Get the raw bytes of the shared secret
    public var rawRepresentation: Data {
        withUnsafeBytes { Data($0) }
    }
}
