/// TLS 1.3 Signature Operations (RFC 8446 Section 4.2.3)
///
/// Supports ECDSA with P-256/P-384 and Ed25519.

import Foundation
import Crypto
import P2PCoreBytes

// MARK: - TLS Signature

/// Signature operations for TLS 1.3
public enum TLSSignature {

    // MARK: - Signing

    /// Sign data using ECDSA with P-256
    /// - Parameters:
    ///   - data: The data to sign
    ///   - privateKey: The P-256 private key
    /// - Returns: The DER-encoded signature
    public static func sign(
        data: Data,
        privateKey: P256.Signing.PrivateKey
    ) throws -> Data {
        let message = [UInt8](data)
        let signing = try TLSDERP256Signature.signingKey(
            rawRepresentation: [UInt8](privateKey.rawRepresentation).span)
        return Data(try TLSDERP256Signature.sign(message.span, with: signing))
    }

    /// Sign data using the specified scheme
    /// - Parameters:
    ///   - data: The data to sign
    ///   - privateKey: The private key (as Data)
    ///   - scheme: The signature scheme
    /// - Returns: The signature
    public static func sign(
        data: Data,
        privateKey: Data,
        scheme: SignatureScheme
    ) throws -> Data {
        switch scheme {
        case .ecdsa_secp256r1_sha256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
            return try sign(data: data, privateKey: key)
        default:
            throw SignatureError.unsupportedScheme(scheme)
        }
    }

    // MARK: - Verification

    /// Verify a signature using ECDSA with P-256
    /// - Parameters:
    ///   - signature: The DER-encoded signature
    ///   - data: The signed data
    ///   - publicKey: The P-256 public key
    /// - Returns: True if the signature is valid
    public static func verify(
        signature: Data,
        for data: Data,
        publicKey: P256.Signing.PublicKey
    ) throws -> Bool {
        let verifying = try TLSDERP256Signature.verifyingKey(
            rawRepresentation: [UInt8](publicKey.x963Representation).span)
        return TLSDERP256Signature.isValid(
            signature: [UInt8](signature).span,
            for: [UInt8](data).span,
            with: verifying)
    }

    /// Verify a signature using the specified scheme
    /// - Parameters:
    ///   - signature: The signature
    ///   - data: The signed data
    ///   - publicKey: The public key (as Data, x963 format)
    ///   - scheme: The signature scheme
    /// - Returns: True if the signature is valid
    public static func verify(
        signature: Data,
        for data: Data,
        publicKey: Data,
        scheme: SignatureScheme
    ) throws -> Bool {
        switch scheme {
        case .ecdsa_secp256r1_sha256:
            let key = try P256.Signing.PublicKey(x963Representation: publicKey)
            return try verify(signature: signature, for: data, publicKey: key)
        default:
            throw SignatureError.unsupportedScheme(scheme)
        }
    }

}

// MARK: - Signature Errors

/// Errors during signature operations
public enum SignatureError: Error, Sendable {
    case unsupportedScheme(SignatureScheme)
    case invalidSignature(String)
    case invalidPublicKey(String)
    case signingFailed(String)
}

// MARK: - Signing Key Wrapper

/// Wrapper for signing keys that supports multiple algorithms
public enum SigningKey: TLSSigningKey, Sendable {
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case ed25519(Curve25519.Signing.PrivateKey)

    /// The signature scheme for this key
    public var scheme: SignatureScheme {
        switch self {
        case .p256: return .ecdsa_secp256r1_sha256
        case .p384: return .ecdsa_secp384r1_sha384
        case .ed25519: return .ed25519
        }
    }

    /// The public key bytes (x963 format for EC, raw for Ed25519)
    public var publicKeyBytes: Data {
        switch self {
        case .p256(let key):
            return Data(key.publicKey.x963Representation)
        case .p384(let key):
            return Data(key.publicKey.x963Representation)
        case .ed25519(let key):
            return Data(key.publicKey.rawRepresentation)
        }
    }

    /// The verification key corresponding to this signing key
    public var verificationKey: VerificationKey {
        switch self {
        case .p256(let key):
            return .p256(key.publicKey)
        case .p384(let key):
            return .p384(key.publicKey)
        case .ed25519(let key):
            return .ed25519(key.publicKey)
        }
    }

    /// Sign data.
    ///
    /// Routes through the `P2PCoreCrypto.SignatureScheme` seam (the
    /// the `TLSDER*Signature` backends) so signing shares the exact code path
    /// `TLSCryptoCore.TLSSignatureSigner` uses. Byte-format-identical to the legacy
    /// direct-CryptoKit path: ECDSA → DER, Ed25519 → raw 64-byte signature.
    public func sign(_ data: Data) throws -> Data {
        let message = [UInt8](data)
        switch self {
        case .p256(let key):
            let signing = try TLSDERP256Signature.signingKey(
                rawRepresentation: [UInt8](key.rawRepresentation).span)
            return Data(try TLSDERP256Signature.sign(message.span, with: signing))
        case .p384(let key):
            let signing = try TLSDERP384Signature.signingKey(
                rawRepresentation: [UInt8](key.rawRepresentation).span)
            return Data(try TLSDERP384Signature.sign(message.span, with: signing))
        case .ed25519(let key):
            let signing = try TLSCryptoProvider.Ed25519.signingKey(
                rawRepresentation: [UInt8](key.rawRepresentation).span)
            return Data(try TLSCryptoProvider.Ed25519.sign(message.span, with: signing))
        }
    }

    /// Generate a new P-256 signing key
    public static func generateP256() -> SigningKey {
        .p256(P256.Signing.PrivateKey())
    }

    /// Generate a new P-384 signing key
    public static func generateP384() -> SigningKey {
        .p384(P384.Signing.PrivateKey())
    }

    /// Generate a new Ed25519 signing key
    public static func generateEd25519() -> SigningKey {
        .ed25519(Curve25519.Signing.PrivateKey())
    }

    /// Build a signing key from a raw private-key representation and scheme.
    ///
    /// Used by the `TLS` facade to translate a `[UInt8]`-currency `TLSIdentity`
    /// into the engine signing key. Throws ``SignatureError/invalidPublicKey`` for
    /// malformed key bytes or an unsupported scheme (no silent fallback).
    public init(rawPrivateKey: [UInt8], scheme: SignatureScheme) throws {
        switch scheme {
        case .ecdsa_secp256r1_sha256:
            self = .p256(try P256.Signing.PrivateKey(rawRepresentation: Data(rawPrivateKey)))
        case .ecdsa_secp384r1_sha384:
            self = .p384(try P384.Signing.PrivateKey(rawRepresentation: Data(rawPrivateKey)))
        case .ed25519:
            self = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: Data(rawPrivateKey)))
        default:
            throw SignatureError.unsupportedScheme(scheme)
        }
    }
}

// MARK: - Verification Key Wrapper

/// Wrapper for verification keys
public enum VerificationKey: TLSVerificationKey, Sendable {
    case p256(P256.Signing.PublicKey)
    case p384(P384.Signing.PublicKey)
    case ed25519(Curve25519.Signing.PublicKey)

    /// Create from public key bytes and scheme
    public init(publicKeyBytes: Data, scheme: SignatureScheme) throws {
        switch scheme {
        case .ecdsa_secp256r1_sha256:
            let key = try P256.Signing.PublicKey(x963Representation: publicKeyBytes)
            self = .p256(key)
        case .ecdsa_secp384r1_sha384:
            let key = try P384.Signing.PublicKey(x963Representation: publicKeyBytes)
            self = .p384(key)
        case .ed25519:
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
            self = .ed25519(key)
        default:
            throw SignatureError.unsupportedScheme(scheme)
        }
    }

    /// The signature scheme for this key
    public var scheme: SignatureScheme {
        switch self {
        case .p256: return .ecdsa_secp256r1_sha256
        case .p384: return .ecdsa_secp384r1_sha384
        case .ed25519: return .ed25519
        }
    }

    /// The public key bytes (x963 format for EC, raw for Ed25519)
    public var publicKeyBytes: Data {
        switch self {
        case .p256(let key):
            return Data(key.x963Representation)
        case .p384(let key):
            return Data(key.x963Representation)
        case .ed25519(let key):
            return Data(key.rawRepresentation)
        }
    }

    /// Verify a signature.
    ///
    /// Routes through the `P2PCoreCrypto.SignatureScheme` seam (the
    /// the `TLSDER*Signature` backends) so verification shares the exact code
    /// path `TLSCryptoCore.TLSSignatureVerifier` uses. An invalid signature is an
    /// explicit `false` — never a silent accept (RFC 8446 §4.4.3 proof of
    /// possession). Byte-input-identical to the legacy direct-CryptoKit path
    /// (ECDSA DER, Ed25519 raw).
    public func verify(signature: Data, for data: Data) throws -> Bool {
        let sig = [UInt8](signature)
        let message = [UInt8](data)
        switch self {
        case .p256(let key):
            let verifying = try TLSDERP256Signature.verifyingKey(
                rawRepresentation: [UInt8](key.x963Representation).span)
            return TLSDERP256Signature.isValid(
                signature: sig.span, for: message.span, with: verifying)
        case .p384(let key):
            let verifying = try TLSDERP384Signature.verifyingKey(
                rawRepresentation: [UInt8](key.x963Representation).span)
            return TLSDERP384Signature.isValid(
                signature: sig.span, for: message.span, with: verifying)
        case .ed25519(let key):
            let verifying = try TLSCryptoProvider.Ed25519.verifyingKey(
                rawRepresentation: [UInt8](key.rawRepresentation).span)
            return TLSCryptoProvider.Ed25519.isValid(
                signature: sig.span, for: message.span, with: verifying)
        }
    }
}
