/// DTLS Certificate and Fingerprint
///
/// Self-signed ECDSA P-256 certificate generation and SHA-256 fingerprint
/// computation for WebRTC usage.

import Foundation
import Crypto
import TLSCore
@preconcurrency import X509
import SwiftASN1

/// A DTLS certificate with its private key and fingerprint
public struct DTLSCertificate: Sendable {
    /// The X.509 certificate (from TLSCore)
    public let x509: X509Certificate

    /// The ECDSA P-256 private key
    public let privateKey: P256.Signing.PrivateKey

    /// SHA-256 fingerprint of the DER-encoded certificate
    public let fingerprint: CertificateFingerprint

    /// Generate a self-signed ECDSA P-256 certificate
    /// - Parameter commonName: The Common Name (CN) for the certificate subject
    /// - Returns: A new self-signed certificate with private key
    public static func generateSelfSigned(
        commonName: String = "webrtc"
    ) throws -> DTLSCertificate {
        let privateKey = P256.Signing.PrivateKey()

        let subject = try DistinguishedName {
            CommonName(commonName)
        }

        let now = Date()
        let certificate = try X509.Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: .init(privateKey.publicKey),
            notValidBefore: now,
            notValidAfter: now.addingTimeInterval(365 * 24 * 60 * 60), // 1 year
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                Critical(
                    try KeyUsage(digitalSignature: true)
                )
            },
            issuerPrivateKey: .init(privateKey)
        )

        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        let derData = Data(serializer.serializedBytes)

        let x509Cert = X509Certificate(certificate, derEncoded: derData)
        let fingerprint = CertificateFingerprint.fromDER(derData)

        return DTLSCertificate(
            x509: x509Cert,
            privateKey: privateKey,
            fingerprint: fingerprint
        )
    }

    /// The DER-encoded certificate data
    public var derEncoded: Data {
        x509.derEncoded
    }

    /// Create a TLSCore SigningKey from this certificate's private key
    public var signingKey: SigningKey {
        .p256(privateKey)
    }
}

/// Fingerprint algorithm
public enum FingerprintAlgorithm: String, Sendable, Hashable {
    case sha256 = "sha-256"
}

/// Certificate fingerprint for WebRTC SDP and multiaddr
public struct CertificateFingerprint: Sendable, Hashable, Equatable {
    /// The hash algorithm used
    public let algorithm: FingerprintAlgorithm

    /// The fingerprint bytes (32 bytes for SHA-256)
    public let bytes: Data

    /// Compute fingerprint from DER-encoded certificate
    /// - Parameter data: DER-encoded X.509 certificate
    /// - Returns: SHA-256 fingerprint
    public static func fromDER(_ data: Data) -> CertificateFingerprint {
        let hash = SHA256.hash(data: data)
        return CertificateFingerprint(
            algorithm: .sha256,
            bytes: Data(hash)
        )
    }

    /// Multihash-encoded fingerprint (0x12 = SHA2-256, 0x20 = 32 bytes)
    public var multihash: Data {
        var result = Data(capacity: 2 + bytes.count)
        result.append(0x12) // SHA2-256 code
        result.append(0x20) // 32 bytes digest length
        result.append(bytes)
        return result
    }

    /// Multibase base64url encoded (prefix 'u')
    public var multibaseEncoded: String {
        let base64url = multihash.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "u" + base64url
    }

    /// SDP fingerprint format: "sha-256 AB:CD:EF:..."
    public var sdpFormat: String {
        let hexParts = bytes.map { String(format: "%02X", $0) }
        return "\(algorithm.rawValue) \(hexParts.joined(separator: ":"))"
    }
}
