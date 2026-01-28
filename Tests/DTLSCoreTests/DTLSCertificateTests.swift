/// Tests for DTLS Certificate and Fingerprint

import Testing
import Foundation
import Crypto
@testable import DTLSCore

@Suite("DTLSCertificate Tests")
struct DTLSCertificateTests {

    @Test("Generate self-signed certificate")
    func generateSelfSigned() throws {
        let cert = try DTLSCertificate.generateSelfSigned(commonName: "test")

        // Verify certificate properties
        #expect(cert.x509.isSelfSigned)
        #expect(cert.x509.subject.commonName?.contains("test") == true)
        #expect(cert.derEncoded.count > 0)

        // Verify fingerprint
        #expect(cert.fingerprint.algorithm == .sha256)
        #expect(cert.fingerprint.bytes.count == 32)
    }

    @Test("Certificate fingerprint is deterministic")
    func fingerprintDeterministic() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let fp1 = CertificateFingerprint.fromDER(cert.derEncoded)
        let fp2 = CertificateFingerprint.fromDER(cert.derEncoded)

        #expect(fp1 == fp2)
        #expect(fp1.bytes == fp2.bytes)
    }

    @Test("Different certificates have different fingerprints")
    func differentFingerprints() throws {
        let cert1 = try DTLSCertificate.generateSelfSigned()
        let cert2 = try DTLSCertificate.generateSelfSigned()

        #expect(cert1.fingerprint != cert2.fingerprint)
    }

    @Test("Multihash encoding")
    func multihashEncoding() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let multihash = cert.fingerprint.multihash

        // SHA2-256 code = 0x12, length = 0x20, hash = 32 bytes
        #expect(multihash.count == 34)
        #expect(multihash[0] == 0x12)
        #expect(multihash[1] == 0x20)
    }

    @Test("Multibase encoding")
    func multibaseEncoding() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let encoded = cert.fingerprint.multibaseEncoded

        // Should start with 'u' (base64url prefix)
        #expect(encoded.hasPrefix("u"))

        // Should not contain padding
        #expect(!encoded.contains("="))
    }

    @Test("SDP format fingerprint")
    func sdpFormat() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let sdp = cert.fingerprint.sdpFormat

        #expect(sdp.hasPrefix("sha-256 "))

        // Should be colon-separated hex pairs
        let parts = sdp.dropFirst("sha-256 ".count).split(separator: ":")
        #expect(parts.count == 32) // 32 bytes = 32 hex pairs
    }

    @Test("Signing key from certificate")
    func signingKey() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let key = cert.signingKey

        // Should be able to sign and verify
        let testData = Data("test data".utf8)
        let signature = try key.sign(testData)
        let valid = try key.verificationKey.verify(signature: signature, for: testData)
        #expect(valid)
    }
}
