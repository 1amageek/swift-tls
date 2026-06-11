/// Raw Public Key Trust Evaluation (RFC 7250 Section 6)
///
/// Raw public keys carry no identity binding or chain of trust, so they
/// must be pre-provisioned through an out-of-band mechanism. A peer's key
/// is trusted when it matches `trustedRawPublicKeys` (full SPKI bytes) or
/// `expectedPeerPublicKey` (raw key bytes).

import Foundation

/// Validates Raw Public Key certificate payloads against configured trust.
public enum RawPublicKeyValidator {

    /// Parses and validates a peer's raw public key certificate entry.
    ///
    /// - Parameters:
    ///   - certificate: The decoded Certificate message
    ///   - configuration: The TLS configuration holding trust anchors
    /// - Returns: The parsed SubjectPublicKeyInfo
    /// - Throws: `TLSHandshakeError.certificateVerificationFailed` when the
    ///   payload is malformed or, with `verifyPeer` enabled, not trusted
    public static func validate(
        certificate: Certificate,
        configuration: TLSConfiguration
    ) throws -> SubjectPublicKeyInfo {
        // RFC 7250 Section 3: the certificate_list contains exactly one
        // entry holding the DER-encoded SubjectPublicKeyInfo.
        guard certificate.certificates.count == 1,
              let spkiData = certificate.certificates.first else {
            throw TLSHandshakeError.certificateVerificationFailed(
                "Raw public key certificate must contain exactly one entry, got \(certificate.certificates.count)"
            )
        }

        let spki: SubjectPublicKeyInfo
        do {
            spki = try SubjectPublicKeyInfo.decode(from: spkiData)
        } catch {
            throw TLSHandshakeError.certificateVerificationFailed(
                "Malformed SubjectPublicKeyInfo: \(error)"
            )
        }

        guard configuration.verifyPeer else {
            // Trust evaluation disabled; CertificateVerify still proves
            // possession of the presented key.
            return spki
        }

        if let trustedKeys = configuration.trustedRawPublicKeys,
           trustedKeys.contains(spkiData) {
            return spki
        }

        if let expectedKey = configuration.expectedPeerPublicKey,
           expectedKey == spki.verificationKey.publicKeyBytes {
            return spki
        }

        throw TLSHandshakeError.certificateVerificationFailed(
            "Raw public key is not in the trusted set"
        )
    }
}
