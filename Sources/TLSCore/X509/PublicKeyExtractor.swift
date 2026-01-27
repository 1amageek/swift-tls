/// Public Key Extraction from X.509 Certificates
///
/// Extracts public keys from X.509 certificates and converts them to VerificationKey
/// for signature verification.

import Foundation
import Crypto
@preconcurrency import X509
import SwiftASN1

// MARK: - Public Key Extraction

extension X509Certificate {
    /// Extracts the public key from this certificate as a TLSVerificationKey
    public func extractPublicKey() throws -> any TLSVerificationKey {
        try publicKey.toVerificationKey()
    }
}

extension X509CertificateBase.PublicKey {
    /// Converts this public key to a TLSVerificationKey
    public func toVerificationKey() throws -> any TLSVerificationKey {
        // Try P256 first
        if let p256Key = P256.Signing.PublicKey(self) {
            return VerificationKey.p256(p256Key)
        }

        // Try P384
        if let p384Key = P384.Signing.PublicKey(self) {
            return VerificationKey.p384(p384Key)
        }

        // Try Ed25519
        if let ed25519Key = Curve25519.Signing.PublicKey(self) {
            return VerificationKey.ed25519(ed25519Key)
        }

        throw X509Error.unsupportedPublicKeyAlgorithm("Unsupported public key type")
    }
}

// MARK: - VerificationKey Extension for X.509

extension VerificationKey {
    /// Creates a VerificationKey from an X.509 certificate
    public init(certificate: X509Certificate) throws {
        guard let key = try certificate.extractPublicKey() as? VerificationKey else {
            throw X509Error.unsupportedPublicKeyAlgorithm("Cannot convert to VerificationKey")
        }
        self = key
    }

    /// Creates a VerificationKey from DER-encoded certificate data
    public init(certificateData: Data) throws {
        let cert = try X509Certificate.parse(from: certificateData)
        guard let key = try cert.extractPublicKey() as? VerificationKey else {
            throw X509Error.unsupportedPublicKeyAlgorithm("Cannot convert to VerificationKey")
        }
        self = key
    }

    /// Creates a VerificationKey from a Certificate.PublicKey
    public init(publicKey: X509CertificateBase.PublicKey) throws {
        guard let key = try publicKey.toVerificationKey() as? VerificationKey else {
            throw X509Error.unsupportedPublicKeyAlgorithm("Cannot convert to VerificationKey")
        }
        self = key
    }
}

// MARK: - Signature Algorithm Mapping

extension SignatureAlgorithmIdentifier {
    /// Maps this algorithm to a SignatureScheme (if applicable)
    /// Note: This property is already defined in X509Certificate.swift
}
