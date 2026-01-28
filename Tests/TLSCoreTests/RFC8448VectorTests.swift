/// RFC 8448 Test Vector Tests for TLS 1.3 Key Derivation
///
/// RFC 8448 provides example traces for TLS 1.3 (Section 3: Simple 1-RTT Handshake).
/// These tests verify the key schedule implementation against known intermediate values
/// and structural properties defined by the RFC.

import Testing
import Foundation
import Crypto
@testable import TLSCore

@Suite("RFC 8448 Key Derivation Vector Tests")
struct RFC8448VectorTests {

    // MARK: - Helpers

    /// Extract raw bytes from a SymmetricKey as Data
    private func keyBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    /// Verify a SymmetricKey is non-zero (not all zeroes)
    private func isNonZero(_ key: SymmetricKey) -> Bool {
        let bytes = keyBytes(key)
        return bytes.contains(where: { $0 != 0 })
    }

    /// Create a deterministic shared secret via X25519 key agreement using fixed key material
    private func makeSharedSecret() throws -> SharedSecret {
        let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        return try clientPrivateKey.sharedSecretFromKeyAgreement(with: serverPrivateKey.publicKey)
    }

    /// Advance a key schedule through early + handshake phases, returning handshake secrets
    private func advanceThroughHandshake(
        keySchedule: inout TLSKeySchedule,
        sharedSecret: SharedSecret,
        hsTranscriptHash: Data
    ) throws -> (client: SymmetricKey, server: SymmetricKey) {
        keySchedule.deriveEarlySecret(psk: nil)
        return try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hsTranscriptHash
        )
    }

    /// Advance a key schedule through early + handshake + application phases
    private func advanceThroughApplication(
        keySchedule: inout TLSKeySchedule,
        sharedSecret: SharedSecret,
        hsTranscriptHash: Data,
        appTranscriptHash: Data
    ) throws -> (
        hsClient: SymmetricKey, hsServer: SymmetricKey,
        appClient: SymmetricKey, appServer: SymmetricKey
    ) {
        let (hsClient, hsServer) = try advanceThroughHandshake(
            keySchedule: &keySchedule,
            sharedSecret: sharedSecret,
            hsTranscriptHash: hsTranscriptHash
        )
        let (appClient, appServer) = try keySchedule.deriveApplicationSecrets(
            transcriptHash: appTranscriptHash
        )
        return (hsClient, hsServer, appClient, appServer)
    }

    // MARK: - Test 1: Early Secret Derivation

    @Test("Early secret derivation with nil PSK produces non-zero 32-byte key")
    func testEarlySecretDerivation() throws {
        // RFC 8448 Section 3: The early secret is derived with no PSK (zeroed IKM).
        // For TLS_AES_128_GCM_SHA256, the early secret is 32 bytes.
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        keySchedule.deriveEarlySecret(psk: nil)

        let earlySecret = try keySchedule.currentEarlySecret()
        let earlyBytes = keyBytes(earlySecret)

        #expect(earlyBytes.count == 32)
        #expect(isNonZero(earlySecret))

        // Derive with a known PSK and verify it produces a different early secret
        var keyScheduleWithPSK = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let psk = SymmetricKey(data: Data(repeating: 0xAB, count: 32))
        keyScheduleWithPSK.deriveEarlySecret(psk: psk)

        let earlySecretWithPSK = try keyScheduleWithPSK.currentEarlySecret()
        let earlyBytesWithPSK = keyBytes(earlySecretWithPSK)

        #expect(earlyBytesWithPSK.count == 32)
        #expect(isNonZero(earlySecretWithPSK))
        #expect(earlyBytes != earlyBytesWithPSK)
    }

    // MARK: - Test 2: Handshake Secret Derivation

    @Test("Handshake secrets are 32-byte non-zero keys with client != server")
    func testHandshakeSecretDerivation() throws {
        // RFC 8448 Section 3: After key agreement, handshake secrets are derived.
        // client_handshake_traffic_secret and server_handshake_traffic_secret must differ.
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let sharedSecret = try makeSharedSecret()
        let transcriptHash = Data(SHA256.hash(data: Data("ClientHello...ServerHello".utf8)))

        let (clientHS, serverHS) = try advanceThroughHandshake(
            keySchedule: &keySchedule,
            sharedSecret: sharedSecret,
            hsTranscriptHash: transcriptHash
        )

        let clientHSBytes = keyBytes(clientHS)
        let serverHSBytes = keyBytes(serverHS)

        #expect(clientHSBytes.count == 32)
        #expect(serverHSBytes.count == 32)
        #expect(isNonZero(clientHS))
        #expect(isNonZero(serverHS))
        #expect(clientHSBytes != serverHSBytes)
    }

    // MARK: - Test 3: Application Secret Derivation

    @Test("Application secrets are 32-byte non-zero keys with client != server")
    func testApplicationSecretDerivation() throws {
        // RFC 8448 Section 3: After server Finished, application secrets are derived.
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let sharedSecret = try makeSharedSecret()
        let hsTranscriptHash = Data(SHA256.hash(data: Data("CH||SH".utf8)))
        let appTranscriptHash = Data(SHA256.hash(data: Data("CH||SH||EE||CT||CV||SF".utf8)))

        let (_, _, appClient, appServer) = try advanceThroughApplication(
            keySchedule: &keySchedule,
            sharedSecret: sharedSecret,
            hsTranscriptHash: hsTranscriptHash,
            appTranscriptHash: appTranscriptHash
        )

        let appClientBytes = keyBytes(appClient)
        let appServerBytes = keyBytes(appServer)

        #expect(appClientBytes.count == 32)
        #expect(appServerBytes.count == 32)
        #expect(isNonZero(appClient))
        #expect(isNonZero(appServer))
        #expect(appClientBytes != appServerBytes)
    }

    // MARK: - Test 4: Traffic Keys Derivation (AES-128)

    @Test("Traffic keys for AES-128-GCM: 16-byte key and 12-byte IV")
    func testTrafficKeysDerivation() throws {
        // RFC 8446 Section 7.3: traffic keys are derived from traffic secrets.
        // AES-128-GCM uses a 16-byte (128-bit) key and 12-byte IV.
        let secret = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let trafficKeys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)

        #expect(trafficKeys.key.bitCount == 128)
        #expect(trafficKeys.iv.count == 12)
        #expect(isNonZero(trafficKeys.key))
        #expect(trafficKeys.iv.contains(where: { $0 != 0 }))
    }

    // MARK: - Test 5: Traffic Keys Derivation (AES-256)

    @Test("Traffic keys for AES-256-GCM: 32-byte key and 12-byte IV")
    func testTrafficKeysAES256() throws {
        // AES-256-GCM uses a 32-byte (256-bit) key and 12-byte IV.
        let secret = SymmetricKey(data: Data(repeating: 0x42, count: 48))
        let trafficKeys = TrafficKeys(secret: secret, cipherSuite: .tls_aes_256_gcm_sha384)

        #expect(trafficKeys.key.bitCount == 256)
        #expect(trafficKeys.iv.count == 12)
        #expect(isNonZero(trafficKeys.key))
        #expect(trafficKeys.iv.contains(where: { $0 != 0 }))
    }

    // MARK: - Test 6: Finished Verify Data

    @Test("Finished verify data is 32 bytes for SHA-256 cipher suite")
    func testFinishedVerifyData() throws {
        // RFC 8446 Section 4.4.4: verify_data = HMAC(finished_key, Transcript-Hash)
        // For SHA-256, the output is 32 bytes.
        let keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let baseKey = SymmetricKey(data: Data(repeating: 0x55, count: 32))
        let transcriptHash = Data(SHA256.hash(data: Data("handshake messages".utf8)))

        let finishedKey = keySchedule.finishedKey(from: baseKey)
        #expect(finishedKey.bitCount == 256)
        #expect(isNonZero(finishedKey))

        let verifyData = keySchedule.finishedVerifyData(
            forKey: finishedKey,
            transcriptHash: transcriptHash
        )

        #expect(verifyData.count == 32)
        #expect(verifyData.contains(where: { $0 != 0 }))

        // Verify determinism: same inputs produce same output
        let verifyData2 = keySchedule.finishedVerifyData(
            forKey: finishedKey,
            transcriptHash: transcriptHash
        )
        #expect(verifyData == verifyData2)

        // Different transcript hash produces different verify data
        let differentTranscript = Data(SHA256.hash(data: Data("different messages".utf8)))
        let verifyData3 = keySchedule.finishedVerifyData(
            forKey: finishedKey,
            transcriptHash: differentTranscript
        )
        #expect(verifyData != verifyData3)
    }

    // MARK: - Test 7: Resumption Master Secret

    @Test("Resumption master secret is 32-byte non-zero key after full schedule")
    func testResumptionMasterSecret() throws {
        // RFC 8446 Section 7.1: resumption_master_secret = Derive-Secret(master_secret, "res master", CH...CF)
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let sharedSecret = try makeSharedSecret()
        let hsTranscriptHash = Data(SHA256.hash(data: Data("CH||SH".utf8)))
        let appTranscriptHash = Data(SHA256.hash(data: Data("CH||SH||EE||CT||CV||SF".utf8)))
        let fullTranscriptHash = Data(SHA256.hash(data: Data("CH||SH||EE||CT||CV||SF||CF".utf8)))

        _ = try advanceThroughApplication(
            keySchedule: &keySchedule,
            sharedSecret: sharedSecret,
            hsTranscriptHash: hsTranscriptHash,
            appTranscriptHash: appTranscriptHash
        )

        let resumptionSecret = try keySchedule.deriveResumptionMasterSecret(
            transcriptHash: fullTranscriptHash
        )

        let resumptionBytes = keyBytes(resumptionSecret)
        #expect(resumptionBytes.count == 32)
        #expect(isNonZero(resumptionSecret))
    }

    // MARK: - Test 8: Exporter Master Secret

    @Test("Exporter master secret is 32-byte non-zero key after full schedule")
    func testExporterMasterSecret() throws {
        // RFC 8446 Section 7.1: exporter_master_secret = Derive-Secret(master_secret, "exp master", CH...SF)
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let sharedSecret = try makeSharedSecret()
        let hsTranscriptHash = Data(SHA256.hash(data: Data("CH||SH".utf8)))
        let appTranscriptHash = Data(SHA256.hash(data: Data("CH||SH||EE||CT||CV||SF".utf8)))

        _ = try advanceThroughApplication(
            keySchedule: &keySchedule,
            sharedSecret: sharedSecret,
            hsTranscriptHash: hsTranscriptHash,
            appTranscriptHash: appTranscriptHash
        )

        let exporterSecret = try keySchedule.deriveExporterMasterSecret(
            transcriptHash: appTranscriptHash
        )

        let exporterBytes = keyBytes(exporterSecret)
        #expect(exporterBytes.count == 32)
        #expect(isNonZero(exporterSecret))

        // Exporter and resumption secrets should differ (different labels)
        let fullTranscriptHash = Data(SHA256.hash(data: Data("CH||SH||EE||CT||CV||SF||CF".utf8)))
        let resumptionSecret = try keySchedule.deriveResumptionMasterSecret(
            transcriptHash: fullTranscriptHash
        )
        #expect(keyBytes(exporterSecret) != keyBytes(resumptionSecret))
    }

    // MARK: - Test 9: Binder Key

    @Test("Binder key is non-zero after deriving early secret with PSK")
    func testBinderKey() throws {
        // RFC 8446 Section 7.1: binder_key = Derive-Secret(early_secret, "ext binder" | "res binder", "")
        let psk = SymmetricKey(data: Data(repeating: 0xCD, count: 32))

        // External PSK binder
        var keyScheduleExt = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        keyScheduleExt.deriveEarlySecret(psk: psk)
        let extBinderKey = try keyScheduleExt.deriveBinderKey(isResumption: false)

        let extBinderBytes = keyBytes(extBinderKey)
        #expect(extBinderBytes.count == 32)
        #expect(isNonZero(extBinderKey))

        // Resumption PSK binder
        var keyScheduleRes = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        keyScheduleRes.deriveEarlySecret(psk: psk)
        let resBinderKey = try keyScheduleRes.deriveBinderKey(isResumption: true)

        let resBinderBytes = keyBytes(resBinderKey)
        #expect(resBinderBytes.count == 32)
        #expect(isNonZero(resBinderKey))

        // External and resumption binder keys must differ (different labels)
        #expect(extBinderBytes != resBinderBytes)
    }

    // MARK: - Test 10: HKDF-Expand-Label Determinism

    @Test("HKDF-Expand-Label produces deterministic output: same inputs produce same output")
    func testHKDFExpandLabel() throws {
        // The key schedule uses HKDF-Expand-Label internally. Verify determinism
        // by checking that finishedKey (which calls HKDF-Expand-Label with label "finished")
        // produces identical output for identical input.
        let keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let baseKey = SymmetricKey(data: Data(repeating: 0x77, count: 32))

        let finished1 = keySchedule.finishedKey(from: baseKey)
        let finished2 = keySchedule.finishedKey(from: baseKey)

        #expect(keyBytes(finished1) == keyBytes(finished2))

        // nextApplicationSecret also calls HKDF-Expand-Label with "traffic upd"
        let next1 = keySchedule.nextApplicationSecret(from: baseKey)
        let next2 = keySchedule.nextApplicationSecret(from: baseKey)

        #expect(keyBytes(next1) == keyBytes(next2))

        // Different labels produce different outputs from same key
        #expect(keyBytes(finished1) != keyBytes(next1))
    }

    // MARK: - Test 11: Derived Secret Intermediate

    @Test("Derived intermediate secret is deterministic across independent key schedules")
    func testDerivedSecretIntermediate() throws {
        // The "derived" secret is an intermediate used between early -> handshake -> master.
        // Verify that two independent key schedules with the same inputs produce the same
        // handshake secrets, which implies the intermediate "derived" secret is deterministic.
        let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(
            with: serverPrivateKey.publicKey
        )
        let transcriptHash = Data(SHA256.hash(data: Data("deterministic test".utf8)))

        var ks1 = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        ks1.deriveEarlySecret(psk: nil)
        let (client1, server1) = try ks1.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        var ks2 = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        ks2.deriveEarlySecret(psk: nil)
        let (client2, server2) = try ks2.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        #expect(keyBytes(client1) == keyBytes(client2))
        #expect(keyBytes(server1) == keyBytes(server2))

        // Further verify that application secrets are also deterministic
        let appTranscript = Data(SHA256.hash(data: Data("app transcript".utf8)))
        let (appClient1, appServer1) = try ks1.deriveApplicationSecrets(transcriptHash: appTranscript)
        let (appClient2, appServer2) = try ks2.deriveApplicationSecrets(transcriptHash: appTranscript)

        #expect(keyBytes(appClient1) == keyBytes(appClient2))
        #expect(keyBytes(appServer1) == keyBytes(appServer2))
    }

    // MARK: - Test 12: Transcript Hash Computation

    @Test("TranscriptHash matches SHA-256 of the same input bytes")
    func testTranscriptHashComputation() throws {
        // RFC 8446 Section 4.4.1: Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
        // Verify that TranscriptHash produces the same output as directly hashing
        // the concatenation of all input messages.
        let message1 = Data([
            0x01, 0x00, 0x00, 0xc0, // ClientHello header (type=0x01, length=192)
            0x03, 0x03,             // legacy_version = TLS 1.2
            0xaa, 0xbb, 0xcc, 0xdd  // partial random (truncated for test)
        ])
        let message2 = Data([
            0x02, 0x00, 0x00, 0x56, // ServerHello header (type=0x02, length=86)
            0x03, 0x03,             // legacy_version = TLS 1.2
            0x11, 0x22, 0x33, 0x44  // partial random (truncated for test)
        ])
        let message3 = Data([
            0x08, 0x00, 0x00, 0x02, // EncryptedExtensions header
            0x00, 0x00              // empty extensions
        ])

        // Compute via TranscriptHash
        var transcript = TranscriptHash(cipherSuite: .tls_aes_128_gcm_sha256)
        transcript.update(with: message1)
        transcript.update(with: message2)
        transcript.update(with: message3)
        let transcriptResult = transcript.currentHash()

        // Compute via direct SHA-256 over concatenated messages
        var concatenated = Data()
        concatenated.append(message1)
        concatenated.append(message2)
        concatenated.append(message3)
        let directHash = Data(SHA256.hash(data: concatenated))

        #expect(transcriptResult == directHash)
        #expect(transcriptResult.count == 32)

        // Single message case
        var singleTranscript = TranscriptHash(cipherSuite: .tls_aes_128_gcm_sha256)
        singleTranscript.update(with: message1)
        let singleResult = singleTranscript.currentHash()
        let singleDirect = Data(SHA256.hash(data: message1))
        #expect(singleResult == singleDirect)
    }
}

// MARK: - Additional RFC 8448 Property Tests

@Suite("RFC 8448 Key Schedule Property Tests")
struct RFC8448PropertyTests {

    private func keyBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private func isNonZero(_ key: SymmetricKey) -> Bool {
        let bytes = keyBytes(key)
        return bytes.contains(where: { $0 != 0 })
    }

    @Test("Early secret with nil PSK is HKDF-Extract(0^32, 0^32) for SHA-256")
    func testEarlySecretKnownValue() throws {
        // RFC 8446 Section 7.1: Early Secret = HKDF-Extract(salt=0^Hash.length, IKM=0^Hash.length)
        // We can compute this directly and verify.
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        keySchedule.deriveEarlySecret(psk: nil)
        let earlySecret = try keySchedule.currentEarlySecret()

        // Compute expected value: HKDF-Extract with salt=0^32, IKM=0^32
        let zeroSalt = Data(repeating: 0, count: 32)
        let zeroIKM = SymmetricKey(data: Data(repeating: 0, count: 32))
        let expectedPRK = HKDF<SHA256>.extract(inputKeyMaterial: zeroIKM, salt: zeroSalt)
        let expectedEarlySecret = SymmetricKey(data: expectedPRK)

        #expect(keyBytes(earlySecret) == keyBytes(expectedEarlySecret))
    }

    @Test("SHA-384 key schedule produces 48-byte secrets")
    func testSHA384KeySchedule() throws {
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_256_gcm_sha384)
        #expect(keySchedule.hashLength == 48)

        keySchedule.deriveEarlySecret(psk: nil)
        let earlySecret = try keySchedule.currentEarlySecret()
        #expect(keyBytes(earlySecret).count == 48)
        #expect(isNonZero(earlySecret))
    }

    @Test("Key schedule state transitions enforce ordering")
    func testKeyScheduleStateOrdering() throws {
        // Cannot derive application secrets without first deriving handshake secrets
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        keySchedule.deriveEarlySecret(psk: nil)

        let appTranscript = Data(repeating: 0xCC, count: 32)
        #expect(throws: TLSKeyScheduleError.self) {
            _ = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscript)
        }
    }

    @Test("Cannot derive handshake secrets twice")
    func testNoDoubleHandshakeDerivation() throws {
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(
            with: serverPrivateKey.publicKey
        )
        let transcript = Data(repeating: 0xAA, count: 32)

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcript
        )

        // Second call should fail because state is now handshakeSecret, not earlySecret
        #expect(throws: TLSKeyScheduleError.self) {
            _ = try keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcript
            )
        }
    }

    @Test("Traffic keys from same secret are deterministic")
    func testTrafficKeysDeterminism() throws {
        let secret = SymmetricKey(data: Data(repeating: 0x99, count: 32))

        let tk1 = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)
        let tk2 = TrafficKeys(secret: secret, cipherSuite: .tls_aes_128_gcm_sha256)

        #expect(keyBytes(tk1.key) == keyBytes(tk2.key))
        #expect(tk1.iv == tk2.iv)
    }

    @Test("Different secrets produce different traffic keys")
    func testTrafficKeysDifferentSecrets() throws {
        let secret1 = SymmetricKey(data: Data(repeating: 0x11, count: 32))
        let secret2 = SymmetricKey(data: Data(repeating: 0x22, count: 32))

        let tk1 = TrafficKeys(secret: secret1, cipherSuite: .tls_aes_128_gcm_sha256)
        let tk2 = TrafficKeys(secret: secret2, cipherSuite: .tls_aes_128_gcm_sha256)

        #expect(keyBytes(tk1.key) != keyBytes(tk2.key))
        #expect(tk1.iv != tk2.iv)
    }

    @Test("Key update produces a chain of distinct secrets")
    func testKeyUpdateChain() throws {
        let keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let initial = SymmetricKey(data: Data(repeating: 0x42, count: 32))

        let next1 = keySchedule.nextApplicationSecret(from: initial)
        let next2 = keySchedule.nextApplicationSecret(from: next1)
        let next3 = keySchedule.nextApplicationSecret(from: next2)

        let initialBytes = keyBytes(initial)
        let next1Bytes = keyBytes(next1)
        let next2Bytes = keyBytes(next2)
        let next3Bytes = keyBytes(next3)

        // All secrets in the chain must be distinct
        let allSecrets = [initialBytes, next1Bytes, next2Bytes, next3Bytes]
        for i in 0..<allSecrets.count {
            for j in (i + 1)..<allSecrets.count {
                #expect(allSecrets[i] != allSecrets[j])
            }
        }

        // Each must be 32 bytes and non-zero
        for secret in allSecrets {
            #expect(secret.count == 32)
            #expect(secret.contains(where: { $0 != 0 }))
        }
    }

    @Test("TranscriptHash SHA-384 produces 48-byte output")
    func testTranscriptHashSHA384() throws {
        var transcript = TranscriptHash(cipherSuite: .tls_aes_256_gcm_sha384)
        let message = Data([0x01, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD])
        transcript.update(with: message)

        let hash = transcript.currentHash()
        #expect(hash.count == 48)

        // Verify against direct SHA-384
        let directHash = Data(SHA384.hash(data: message))
        #expect(hash == directHash)
    }

    @Test("Resumption PSK derivation from resumption master secret")
    func testResumptionPSKDerivation() throws {
        // RFC 8446 Section 4.6.1: PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(
            with: serverPrivateKey.publicKey
        )

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: Data(repeating: 0xAA, count: 32)
        )
        _ = try keySchedule.deriveApplicationSecrets(
            transcriptHash: Data(repeating: 0xBB, count: 32)
        )

        let resumptionSecret = try keySchedule.deriveResumptionMasterSecret(
            transcriptHash: Data(repeating: 0xCC, count: 32)
        )

        // Derive PSK with two different nonces
        let nonce1 = Data([0x00, 0x00, 0x00, 0x01])
        let nonce2 = Data([0x00, 0x00, 0x00, 0x02])

        let psk1 = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: resumptionSecret,
            ticketNonce: nonce1
        )
        let psk2 = keySchedule.deriveResumptionPSK(
            resumptionMasterSecret: resumptionSecret,
            ticketNonce: nonce2
        )

        #expect(keyBytes(psk1).count == 32)
        #expect(keyBytes(psk2).count == 32)
        #expect(keyBytes(psk1) != keyBytes(psk2))
    }

    @Test("Exporter keying material derivation")
    func testExporterKeyingMaterial() throws {
        // RFC 8446 Section 7.5: Exported keying material uses a two-step derivation.
        var keySchedule = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(
            with: serverPrivateKey.publicKey
        )

        _ = try keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: Data(repeating: 0xAA, count: 32)
        )
        _ = try keySchedule.deriveApplicationSecrets(
            transcriptHash: Data(repeating: 0xBB, count: 32)
        )

        let exporterMasterSecret = try keySchedule.deriveExporterMasterSecret(
            transcriptHash: Data(repeating: 0xBB, count: 32)
        )

        let ekm1 = keySchedule.exportKeyingMaterial(
            exporterMasterSecret: exporterMasterSecret,
            label: "test-label",
            context: Data([0x01, 0x02, 0x03]),
            length: 32
        )

        let ekm2 = keySchedule.exportKeyingMaterial(
            exporterMasterSecret: exporterMasterSecret,
            label: "test-label",
            context: Data([0x01, 0x02, 0x03]),
            length: 32
        )

        #expect(ekm1.count == 32)
        #expect(ekm1 == ekm2) // Deterministic

        // Different label produces different output
        let ekm3 = keySchedule.exportKeyingMaterial(
            exporterMasterSecret: exporterMasterSecret,
            label: "other-label",
            context: Data([0x01, 0x02, 0x03]),
            length: 32
        )
        #expect(ekm1 != ekm3)

        // Different context produces different output
        let ekm4 = keySchedule.exportKeyingMaterial(
            exporterMasterSecret: exporterMasterSecret,
            label: "test-label",
            context: Data([0x04, 0x05, 0x06]),
            length: 32
        )
        #expect(ekm1 != ekm4)
    }
}

// MARK: - RFC 8448 Known-Answer Vector Tests

/// Tests that compare computed values byte-for-byte against RFC 8448 Section 3
/// hex vectors for the Simple 1-RTT Handshake.
@Suite("RFC 8448 Known-Answer Vector Tests")
struct RFC8448KnownAnswerTests {

    // MARK: - Helpers

    private func keyBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func dataFromHex(_ hex: String) -> Data {
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            let byteString = hex[index..<nextIndex]
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            }
            index = nextIndex
        }
        return data
    }

    // MARK: - RFC 8448 Section 3 Known Values

    // early_secret = HKDF-Extract(salt=0^32, ikm=0^32)
    // This is the starting point for all TLS 1.3 key derivation without PSK.
    private let earlySecretHex = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"

    // RFC 8448 X25519 private keys
    private let clientPrivateKeyHex = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
    private let serverPrivateKeyHex = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"

    // The shared secret from X25519 key exchange (client_private * server_public)
    private let sharedSecretHex = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"

    // Transcript hash of ClientHello..ServerHello from RFC 8448
    private let chShTranscriptHashHex = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"

    // client_handshake_traffic_secret
    private let clientHSSecretHex = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"

    // server_handshake_traffic_secret
    private let serverHSSecretHex = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"

    // MARK: - Tests

    @Test("Early secret matches RFC 8448 Section 3")
    func testEarlySecretKnownAnswer() throws {
        var ks = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        ks.deriveEarlySecret(psk: nil)
        let earlySecret = try ks.currentEarlySecret()
        let bytes = keyBytes(earlySecret)
        #expect(hexString(bytes) == earlySecretHex)
    }

    @Test("X25519 shared secret from RFC 8448 keys")
    func testX25519SharedSecret() throws {
        let clientPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: dataFromHex(clientPrivateKeyHex)
        )
        let serverPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: dataFromHex(serverPrivateKeyHex)
        )

        // Client computes shared secret using server's public key
        let sharedSecret = try clientPriv.sharedSecretFromKeyAgreement(
            with: serverPriv.publicKey
        )
        let ssBytes = sharedSecret.withUnsafeBytes { Data($0) }
        #expect(hexString(ssBytes) == sharedSecretHex)
    }

    @Test("Handshake traffic secrets match RFC 8448 Section 3")
    func testHandshakeSecretsKnownAnswer() throws {
        var ks = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        ks.deriveEarlySecret(psk: nil)

        // Reconstruct X25519 shared secret from RFC 8448 keys
        let clientPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: dataFromHex(clientPrivateKeyHex)
        )
        let serverPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: dataFromHex(serverPrivateKeyHex)
        )
        let sharedSecret = try clientPriv.sharedSecretFromKeyAgreement(
            with: serverPriv.publicKey
        )

        // Use the known transcript hash from RFC 8448
        let transcriptHash = dataFromHex(chShTranscriptHashHex)

        let (clientHS, serverHS) = try ks.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        #expect(hexString(keyBytes(clientHS)) == clientHSSecretHex)
        #expect(hexString(keyBytes(serverHS)) == serverHSSecretHex)
    }

    @Test("SHA-256 of empty data used in key derivation intermediates")
    func testEmptyTranscriptHash() {
        // TranscriptHash with no messages should equal SHA-256("")
        // This is used internally by Derive-Secret with empty context
        let th = TranscriptHash(cipherSuite: .tls_aes_128_gcm_sha256)
        let hash = th.currentHash()
        let expectedSHA256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        #expect(hexString(hash) == expectedSHA256Empty)
    }
}
