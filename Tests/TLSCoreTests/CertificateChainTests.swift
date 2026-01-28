/// Certificate Chain Validation Tests
///
/// Tests X509Validator, CertificateStore, hostname verification, and
/// signing/verification key generation using the swift-certificates library.

import Testing
import Foundation
import Crypto
@testable import TLSCore
@preconcurrency import X509
import SwiftASN1

@Suite("Certificate Chain Validation Tests")
struct CertificateChainTests {

    // MARK: - Helpers

    /// Converts a swift-certificates Certificate to an X509Certificate.
    private static func toX509Certificate(_ certificate: X509.Certificate) throws -> X509Certificate {
        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        let derData = Data(serializer.serializedBytes)
        return X509Certificate(certificate, derEncoded: derData)
    }

    /// Creates a self-signed CA X509Certificate.
    private static func createSelfSignedCA(
        commonName: String = "Test CA",
        notValidBefore: Date = Date().addingTimeInterval(-3600),
        notValidAfter: Date = Date().addingTimeInterval(3600),
        key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()
    ) throws -> (X509Certificate, P256.Signing.PrivateKey) {
        let name = try DistinguishedName {
            CommonName(commonName)
            OrganizationName("Test Org")
        }

        let certificate = try X509.Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                KeyUsage(keyCertSign: true)
            },
            issuerPrivateKey: Certificate.PrivateKey(key)
        )

        return (try toX509Certificate(certificate), key)
    }

    /// Creates a self-signed leaf X509Certificate with SAN DNS names.
    private static func createSelfSignedLeaf(
        commonName: String = "leaf.example.com",
        dnsNames: [String] = [],
        notValidBefore: Date = Date().addingTimeInterval(-3600),
        notValidAfter: Date = Date().addingTimeInterval(3600),
        key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()
    ) throws -> (X509Certificate, P256.Signing.PrivateKey) {
        let name = try DistinguishedName {
            CommonName(commonName)
            OrganizationName("Test Org")
        }

        let sanEntries: [GeneralName] = dnsNames.map { .dnsName($0) }

        let certificate = try X509.Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                KeyUsage(digitalSignature: true)
                if !sanEntries.isEmpty {
                    SubjectAlternativeNames(sanEntries)
                }
            },
            issuerPrivateKey: Certificate.PrivateKey(key)
        )

        return (try toX509Certificate(certificate), key)
    }

    /// Creates a leaf certificate signed by a given CA.
    private static func createSignedLeaf(
        commonName: String = "leaf.example.com",
        dnsNames: [String] = ["leaf.example.com"],
        issuerName: String = "Test CA",
        issuerKey: P256.Signing.PrivateKey,
        notValidBefore: Date = Date().addingTimeInterval(-3600),
        notValidAfter: Date = Date().addingTimeInterval(3600)
    ) throws -> (X509Certificate, P256.Signing.PrivateKey) {
        let leafKey = P256.Signing.PrivateKey()
        let issuer = try DistinguishedName {
            CommonName(issuerName)
            OrganizationName("Test Org")
        }
        let subject = try DistinguishedName {
            CommonName(commonName)
            OrganizationName("Test Org")
        }

        let sanEntries: [GeneralName] = dnsNames.map { .dnsName($0) }

        let certificate = try X509.Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(leafKey.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                KeyUsage(digitalSignature: true)
                if !sanEntries.isEmpty {
                    SubjectAlternativeNames(sanEntries)
                }
            },
            issuerPrivateKey: Certificate.PrivateKey(issuerKey)
        )

        return (try toX509Certificate(certificate), leafKey)
    }

    // MARK: - Self-Signed Certificate Tests

    @Test("Self-signed certificate accepted when allowSelfSigned is true")
    func testSelfSignedCertificateAccepted() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "self-signed.example.com",
            dnsNames: ["self-signed.example.com"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: true,
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: Never.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Self-signed certificate rejected when allowSelfSigned is false")
    func testSelfSignedCertificateRejected() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "self-signed.example.com",
            dnsNames: ["self-signed.example.com"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: true,
            allowSelfSigned: false
        )

        let validator = X509Validator(options: options)
        #expect(throws: X509Error.self) {
            try validator.validate(certificate: cert)
        }
    }

    // MARK: - Expired Certificate Tests

    @Test("Expired certificate rejected")
    func testExpiredCertificateRejected() throws {
        let pastDate = Date().addingTimeInterval(-7200)
        let expiredDate = Date().addingTimeInterval(-3600)

        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "expired.example.com",
            dnsNames: ["expired.example.com"],
            notValidBefore: pastDate,
            notValidAfter: expiredDate
        )

        let options = X509ValidationOptions(
            checkValidity: true,
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: X509Error.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Not-yet-valid certificate rejected")
    func testNotYetValidCertificateRejected() throws {
        let futureStart = Date().addingTimeInterval(3600)
        let futureEnd = Date().addingTimeInterval(7200)

        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "future.example.com",
            dnsNames: ["future.example.com"],
            notValidBefore: futureStart,
            notValidAfter: futureEnd
        )

        let options = X509ValidationOptions(
            checkValidity: true,
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: X509Error.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Certificate validity period check can be disabled")
    func testValidityCheckDisabled() throws {
        let pastDate = Date().addingTimeInterval(-7200)
        let expiredDate = Date().addingTimeInterval(-3600)

        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "expired.example.com",
            dnsNames: ["expired.example.com"],
            notValidBefore: pastDate,
            notValidAfter: expiredDate
        )

        let options = X509ValidationOptions(
            checkValidity: false,
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: Never.self) {
            try validator.validate(certificate: cert)
        }
    }

    // MARK: - Hostname Verification Tests

    @Test("Hostname exact match succeeds")
    func testHostnameExactMatch() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "www.example.com",
            dnsNames: ["www.example.com"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            hostname: "www.example.com",
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: Never.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Hostname wildcard match succeeds")
    func testHostnameWildcardMatch() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "*.example.com",
            dnsNames: ["*.example.com"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            hostname: "www.example.com",
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: Never.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Hostname wildcard does not match bare domain")
    func testHostnameWildcardNoBareDomain() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "*.example.com",
            dnsNames: ["*.example.com"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            hostname: "example.com",
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: X509Error.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Hostname mismatch rejected")
    func testHostnameMismatchRejected() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "www.example.com",
            dnsNames: ["www.example.com"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            hostname: "www.evil.com",
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: X509Error.self) {
            try validator.validate(certificate: cert)
        }
    }

    @Test("Hostname matching is case-insensitive")
    func testHostnameCaseInsensitive() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "WWW.EXAMPLE.COM",
            dnsNames: ["WWW.EXAMPLE.COM"]
        )

        let options = X509ValidationOptions(
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            hostname: "www.example.com",
            allowSelfSigned: true
        )

        let validator = X509Validator(options: options)
        #expect(throws: Never.self) {
            try validator.validate(certificate: cert)
        }
    }

    // MARK: - Certificate Store Tests

    @Test("CertificateStore add and retrieve")
    func testCertificateStoreAddAndRetrieve() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedCA(commonName: "Root CA")

        var store = TLSCore.CertificateStore()
        #expect(store.all.isEmpty)

        store.add(cert)
        #expect(store.all.count == 1)
        #expect(store.all[0].subject.commonName?.contains("Root CA") == true)
    }

    @Test("CertificateStore initialized with certificates")
    func testCertificateStoreInitWithCerts() throws {
        let (cert1, _) = try CertificateChainTests.createSelfSignedCA(commonName: "CA 1")
        let (cert2, _) = try CertificateChainTests.createSelfSignedCA(commonName: "CA 2")

        let store = TLSCore.CertificateStore(certificates: [cert1, cert2])
        #expect(store.all.count == 2)
    }

    @Test("CertificateStore produces validator")
    func testCertificateStoreValidator() throws {
        let (caCert, caKey) = try CertificateChainTests.createSelfSignedCA(commonName: "Root CA")

        let store = TLSCore.CertificateStore(certificates: [caCert])
        let options = X509ValidationOptions(
            checkExtendedKeyUsage: false,
            validateSANFormat: false
        )
        let validator = store.validator(options: options)

        let (leafCert, _) = try CertificateChainTests.createSignedLeaf(
            commonName: "leaf.example.com",
            dnsNames: ["leaf.example.com"],
            issuerName: "Root CA",
            issuerKey: caKey
        )

        #expect(throws: Never.self) {
            try validator.validate(certificate: leafCert, intermediates: [])
        }
    }

    @Test("CertificateStore add DER-encoded data")
    func testCertificateStoreAddDER() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedCA(commonName: "DER CA")

        var store = TLSCore.CertificateStore()
        try store.add(derEncoded: cert.derEncoded)
        #expect(store.all.count == 1)
    }

    // MARK: - Empty Chain Tests

    @Test("Empty certificate chain error is well-formed")
    func testEmptyCertificateChain() throws {
        // The validate method requires at least one certificate (the leaf).
        // X509Error.emptyChain is the expected error when chain building
        // produces an empty chain. Verify the error is well-formed.
        let error = X509Error.emptyChain
        #expect(error.description.contains("empty"))

        // Also verify the error conforms to LocalizedError
        #expect(error.errorDescription != nil)
        #expect(error.errorDescription?.contains("empty") == true)
    }

    // MARK: - Chain with Trusted Root

    @Test("Certificate chain with trusted root validates")
    func testChainWithTrustedRoot() throws {
        let (caCert, caKey) = try CertificateChainTests.createSelfSignedCA(commonName: "Root CA")

        let (leafCert, _) = try CertificateChainTests.createSignedLeaf(
            commonName: "leaf.example.com",
            dnsNames: ["leaf.example.com"],
            issuerName: "Root CA",
            issuerKey: caKey
        )

        let options = X509ValidationOptions(
            checkExtendedKeyUsage: false,
            validateSANFormat: true,
            hostname: "leaf.example.com"
        )

        let validator = X509Validator(trustedRoots: [caCert], options: options)
        #expect(throws: Never.self) {
            try validator.validate(certificate: leafCert, intermediates: [])
        }
    }

    @Test("Certificate chain with untrusted root fails")
    func testChainWithUntrustedRoot() throws {
        let caKey = P256.Signing.PrivateKey()

        let (leafCert, _) = try CertificateChainTests.createSignedLeaf(
            commonName: "leaf.example.com",
            dnsNames: ["leaf.example.com"],
            issuerName: "Unknown CA",
            issuerKey: caKey
        )

        let options = X509ValidationOptions(
            checkExtendedKeyUsage: false,
            validateSANFormat: false,
            allowSelfSigned: false
        )

        let validator = X509Validator(trustedRoots: [], options: options)
        #expect(throws: X509Error.self) {
            try validator.validate(certificate: leafCert, intermediates: [])
        }
    }

    // MARK: - Signing Key Generation Tests

    @Test("SigningKey generation P-256 produces non-empty public key bytes")
    func testSigningKeyGenerationP256() {
        let key = SigningKey.generateP256()
        #expect(key.scheme == .ecdsa_secp256r1_sha256)
        #expect(!key.publicKeyBytes.isEmpty)
        // P-256 x963 representation is 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
        #expect(key.publicKeyBytes.count == 65)
    }

    @Test("SigningKey generation P-384 produces non-empty public key bytes")
    func testSigningKeyGenerationP384() {
        let key = SigningKey.generateP384()
        #expect(key.scheme == .ecdsa_secp384r1_sha384)
        #expect(!key.publicKeyBytes.isEmpty)
        // P-384 x963 representation is 97 bytes (0x04 + 48 bytes X + 48 bytes Y)
        #expect(key.publicKeyBytes.count == 97)
    }

    @Test("SigningKey generation Ed25519 produces non-empty public key bytes")
    func testSigningKeyGenerationEd25519() {
        let key = SigningKey.generateEd25519()
        #expect(key.scheme == .ed25519)
        #expect(!key.publicKeyBytes.isEmpty)
        // Ed25519 raw representation is 32 bytes
        #expect(key.publicKeyBytes.count == 32)
    }

    // MARK: - Verification Key Tests

    @Test("VerificationKey from SigningKey retains scheme")
    func testVerificationKeyFromSigningKey() throws {
        let p256Signing = SigningKey.generateP256()
        let p256Verify = p256Signing.verificationKey
        #expect(p256Verify.scheme == .ecdsa_secp256r1_sha256)

        let p384Signing = SigningKey.generateP384()
        let p384Verify = p384Signing.verificationKey
        #expect(p384Verify.scheme == .ecdsa_secp384r1_sha384)

        let ed25519Signing = SigningKey.generateEd25519()
        let ed25519Verify = ed25519Signing.verificationKey
        #expect(ed25519Verify.scheme == .ed25519)
    }

    @Test("VerificationKey can verify signature from corresponding SigningKey")
    func testVerificationKeyVerifiesSignature() throws {
        let signingKey = SigningKey.generateP256()
        let verificationKey = signingKey.verificationKey

        let data = Data("certificate chain test data".utf8)
        let signature = try signingKey.sign(data)
        let isValid = try verificationKey.verify(signature: signature, for: data)
        #expect(isValid == true)
    }

    @Test("VerificationKey rejects signature from different key")
    func testVerificationKeyRejectsDifferentKey() throws {
        let signingKey1 = SigningKey.generateP256()
        let signingKey2 = SigningKey.generateP256()

        let data = Data("certificate chain test data".utf8)
        let signature = try signingKey1.sign(data)
        let isValid = try signingKey2.verificationKey.verify(signature: signature, for: data)
        #expect(isValid == false)
    }

    // MARK: - Different Key Types Tests

    @Test("Different key types produce different public key bytes")
    func testDifferentKeyTypesNotEqual() {
        let p256Key = SigningKey.generateP256()
        let p384Key = SigningKey.generateP384()
        let ed25519Key = SigningKey.generateEd25519()

        // Different key types have different byte lengths
        #expect(p256Key.publicKeyBytes.count != p384Key.publicKeyBytes.count)
        #expect(p256Key.publicKeyBytes.count != ed25519Key.publicKeyBytes.count)
        #expect(p384Key.publicKeyBytes.count != ed25519Key.publicKeyBytes.count)

        // Different schemes
        #expect(p256Key.scheme != p384Key.scheme)
        #expect(p256Key.scheme != ed25519Key.scheme)
        #expect(p384Key.scheme != ed25519Key.scheme)
    }

    @Test("Two P-256 keys produce different public key bytes")
    func testTwoP256KeysDiffer() {
        let key1 = SigningKey.generateP256()
        let key2 = SigningKey.generateP256()
        #expect(key1.publicKeyBytes != key2.publicKeyBytes)
    }

    // MARK: - X509Validity Tests

    @Test("X509Validity isValid check")
    func testX509ValidityIsValid() {
        let now = Date()
        let validity = X509Validity(
            notBefore: now.addingTimeInterval(-3600),
            notAfter: now.addingTimeInterval(3600)
        )
        #expect(validity.isValid(at: now) == true)
        #expect(validity.isValid(at: now.addingTimeInterval(-7200)) == false)
        #expect(validity.isValid(at: now.addingTimeInterval(7200)) == false)
    }

    // MARK: - Validation Options Tests

    @Test("X509ValidationOptions default values")
    func testValidationOptionsDefaults() {
        let options = X509ValidationOptions()
        #expect(options.checkValidity == true)
        #expect(options.checkBasicConstraints == true)
        #expect(options.checkKeyUsage == true)
        #expect(options.checkExtendedKeyUsage == true)
        #expect(options.validateSANFormat == true)
        #expect(options.checkNameConstraints == true)
        #expect(options.hostname == nil)
        #expect(options.allowSelfSigned == false)
        #expect(options.maxChainDepth == 10)
        #expect(options.requiredEKU == nil)
    }

    @Test("X509ValidationOptions custom values")
    func testValidationOptionsCustom() {
        let options = X509ValidationOptions(
            checkValidity: false,
            checkBasicConstraints: false,
            checkKeyUsage: false,
            checkExtendedKeyUsage: false,
            requiredEKU: .serverAuth,
            validateSANFormat: false,
            checkNameConstraints: false,
            hostname: "test.example.com",
            allowSelfSigned: true,
            maxChainDepth: 5
        )
        #expect(options.checkValidity == false)
        #expect(options.checkBasicConstraints == false)
        #expect(options.checkKeyUsage == false)
        #expect(options.checkExtendedKeyUsage == false)
        #expect(options.validateSANFormat == false)
        #expect(options.checkNameConstraints == false)
        #expect(options.hostname == "test.example.com")
        #expect(options.allowSelfSigned == true)
        #expect(options.maxChainDepth == 5)
    }

    // MARK: - RequiredEKU OID Tests

    @Test("RequiredEKU returns correct OIDs")
    func testRequiredEKUOIDs() {
        #expect(RequiredEKU.serverAuth.oid == "1.3.6.1.5.5.7.3.1")
        #expect(RequiredEKU.clientAuth.oid == "1.3.6.1.5.5.7.3.2")
        #expect(RequiredEKU.codeSigning.oid == "1.3.6.1.5.5.7.3.3")
        #expect(RequiredEKU.emailProtection.oid == "1.3.6.1.5.5.7.3.4")
        #expect(RequiredEKU.timeStamping.oid == "1.3.6.1.5.5.7.3.8")
        #expect(RequiredEKU.ocspSigning.oid == "1.3.6.1.5.5.7.3.9")
    }

    // MARK: - X509Certificate Property Tests

    @Test("X509Certificate exposes correct properties")
    func testCertificateProperties() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "props.example.com",
            dnsNames: ["props.example.com"]
        )

        #expect(cert.subject.commonName?.contains("props.example.com") == true)
        #expect(cert.issuer.commonName?.contains("props.example.com") == true)
        #expect(cert.isSelfSigned == true)
        #expect(cert.isCA == false)
        #expect(cert.version == 2) // v3 = 2
        #expect(!cert.serialNumber.isEmpty)
        #expect(!cert.derEncoded.isEmpty)
        #expect(!cert.tbsCertificateBytes.isEmpty)
        #expect(!cert.signatureValue.isEmpty)
        #expect(!cert.subjectPublicKeyInfoDER.isEmpty)
    }

    @Test("X509Certificate CA properties")
    func testCACertificateProperties() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedCA(commonName: "Test Root CA")

        #expect(cert.isCA == true)
        #expect(cert.isSelfSigned == true)
        #expect(cert.basicConstraints != nil)
        #expect(cert.basicConstraints?.isCA == true)
    }

    @Test("X509Certificate SAN extension is accessible")
    func testCertificateSANExtension() throws {
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "san.example.com",
            dnsNames: ["san.example.com", "alt.example.com"]
        )

        let san = cert.subjectAlternativeNames
        #expect(san != nil)
        let dnsNames = san?.dnsNames ?? []
        #expect(dnsNames.contains("san.example.com"))
        #expect(dnsNames.contains("alt.example.com"))
    }

    // MARK: - Public Key Extraction Tests

    @Test("extractPublicKey returns valid verification key")
    func testExtractPublicKey() throws {
        let key = P256.Signing.PrivateKey()
        let (cert, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "key-extract.example.com",
            key: key
        )

        let verificationKey = try cert.extractPublicKey()
        #expect(verificationKey.scheme == .ecdsa_secp256r1_sha256)

        // Verify a signature made by the private key
        let data = Data("extract key test".utf8)
        let signingKey = SigningKey.p256(key)
        let signature = try signingKey.sign(data)
        let isValid = try verificationKey.verify(signature: signature, for: data)
        #expect(isValid == true)
    }

    // MARK: - Certificate Parsing Tests

    @Test("X509Certificate round-trips through DER parsing")
    func testCertificateDERRoundTrip() throws {
        let (original, _) = try CertificateChainTests.createSelfSignedLeaf(
            commonName: "roundtrip.example.com",
            dnsNames: ["roundtrip.example.com"]
        )

        let parsed = try X509Certificate.parse(from: original.derEncoded)
        #expect(parsed.subject.commonName?.contains("roundtrip.example.com") == true)
        #expect(parsed.isSelfSigned == true)
        #expect(parsed.serialNumber == original.serialNumber)
    }

    @Test("X509Certificate parse rejects invalid DER data")
    func testCertificateParseRejectsInvalid() {
        let invalidData = Data([0x00, 0x01, 0x02, 0x03])
        #expect(throws: X509Error.self) {
            _ = try X509Certificate.parse(from: invalidData)
        }
    }
}
