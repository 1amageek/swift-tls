/// TLS Signing Key Protocol Tests
///
/// Tests that TLSSigningKey and TLSVerificationKey protocols work correctly
/// with the existing SigningKey/VerificationKey enums and custom implementations.

import Testing
import Foundation
import Crypto

@testable import TLSCore

@Suite("Signing Key Protocol Tests")
struct SigningKeyProtocolTests {

    // MARK: - SigningKey Conforms to TLSSigningKey

    @Test("SigningKey P256 conforms to TLSSigningKey")
    func signingKeyP256Conformance() throws {
        let key = SigningKey.generateP256()
        let tlsKey: any TLSSigningKey = key

        #expect(tlsKey.scheme == .ecdsa_secp256r1_sha256)
        #expect(!tlsKey.publicKeyBytes.isEmpty)

        // Sign data
        let data = Data("test data".utf8)
        let signature = try tlsKey.sign(data)
        #expect(!signature.isEmpty)
    }

    @Test("SigningKey P384 conforms to TLSSigningKey")
    func signingKeyP384Conformance() throws {
        let key = SigningKey.generateP384()
        let tlsKey: any TLSSigningKey = key

        #expect(tlsKey.scheme == .ecdsa_secp384r1_sha384)
        #expect(!tlsKey.publicKeyBytes.isEmpty)

        let data = Data("test data".utf8)
        let signature = try tlsKey.sign(data)
        #expect(!signature.isEmpty)
    }

    @Test("SigningKey Ed25519 conforms to TLSSigningKey")
    func signingKeyEd25519Conformance() throws {
        let key = SigningKey.generateEd25519()
        let tlsKey: any TLSSigningKey = key

        #expect(tlsKey.scheme == .ed25519)
        #expect(!tlsKey.publicKeyBytes.isEmpty)

        let data = Data("test data".utf8)
        let signature = try tlsKey.sign(data)
        #expect(!signature.isEmpty)
    }

    // MARK: - VerificationKey Conforms to TLSVerificationKey

    @Test("VerificationKey P256 conforms to TLSVerificationKey")
    func verificationKeyP256Conformance() throws {
        let signingKey = SigningKey.generateP256()
        let verifyKey: any TLSVerificationKey = signingKey.verificationKey

        #expect(verifyKey.scheme == .ecdsa_secp256r1_sha256)

        // Sign and verify
        let data = Data("verification test".utf8)
        let signature = try signingKey.sign(data)
        let isValid = try verifyKey.verify(signature: signature, for: data)
        #expect(isValid == true)
    }

    @Test("VerificationKey rejects invalid signature")
    func verificationKeyRejectsInvalid() throws {
        let signingKey = SigningKey.generateP256()
        let verifyKey: any TLSVerificationKey = signingKey.verificationKey

        let data = Data("original data".utf8)
        let signature = try signingKey.sign(data)

        // Verify with different data should fail
        let differentData = Data("different data".utf8)
        let isValid = try verifyKey.verify(signature: signature, for: differentData)
        #expect(isValid == false)
    }

    // MARK: - Custom Implementation

    @Test("Custom TLSSigningKey implementation")
    func customSigningKey() throws {
        let customKey = MockSigningKey()
        let tlsKey: any TLSSigningKey = customKey

        #expect(tlsKey.scheme == .ecdsa_secp256r1_sha256)
        let signature = try tlsKey.sign(Data("test".utf8))
        #expect(signature == Data("mock-signature".utf8))
    }

    @Test("Custom TLSVerificationKey implementation")
    func customVerificationKey() throws {
        let customKey = MockVerificationKey()
        let tlsKey: any TLSVerificationKey = customKey

        #expect(tlsKey.scheme == .ecdsa_secp256r1_sha256)
        let isValid = try tlsKey.verify(signature: Data(), for: Data())
        #expect(isValid == true)
    }

    // MARK: - TLSConfiguration with Protocol Types

    @Test("TLSConfiguration accepts TLSSigningKey")
    func configAcceptsSigningKey() {
        var config = TLSConfiguration()
        let key = SigningKey.generateP256()
        config.signingKey = key

        #expect(config.signingKey != nil)
        #expect(config.signingKey?.scheme == .ecdsa_secp256r1_sha256)
    }

    @Test("TLSConfiguration accepts custom TLSSigningKey")
    func configAcceptsCustomSigningKey() {
        var config = TLSConfiguration()
        config.signingKey = MockSigningKey()

        #expect(config.signingKey != nil)
        #expect(config.signingKey?.scheme == .ecdsa_secp256r1_sha256)
    }

    // MARK: - HandshakeContext with Protocol Types

    @Test("HandshakeContext accepts TLSVerificationKey")
    func contextAcceptsVerificationKey() {
        var context = HandshakeContext()
        let key = SigningKey.generateP256()
        context.peerVerificationKey = key.verificationKey

        #expect(context.peerVerificationKey != nil)
        #expect(context.peerVerificationKey?.scheme == .ecdsa_secp256r1_sha256)
    }

    @Test("HandshakeContext accepts custom TLSVerificationKey")
    func contextAcceptsCustomVerificationKey() {
        var context = HandshakeContext()
        context.peerVerificationKey = MockVerificationKey()

        #expect(context.peerVerificationKey != nil)
    }
}

// MARK: - Mock Implementations

/// Mock signing key for testing custom implementations
private struct MockSigningKey: TLSSigningKey {
    var scheme: SignatureScheme { .ecdsa_secp256r1_sha256 }
    var publicKeyBytes: Data { Data("mock-public-key".utf8) }

    func sign(_ data: Data) throws -> Data {
        Data("mock-signature".utf8)
    }
}

/// Mock verification key for testing custom implementations
private struct MockVerificationKey: TLSVerificationKey {
    var scheme: SignatureScheme { .ecdsa_secp256r1_sha256 }

    func verify(signature: Data, for data: Data) throws -> Bool {
        true // Always valid for mock
    }
}
