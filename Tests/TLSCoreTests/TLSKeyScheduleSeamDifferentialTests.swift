/// Differential tests for the seam-routed TLS 1.3 key schedule.
///
/// Asserts that the Embedded-clean `TLSCryptoCore.TLSKeySchedule<C>` specialised
/// at `C = TLSProvider` produces byte-for-byte the RFC 8448 Section 3
/// vectors directly through the `CryptoProvider`/`KeyDerivation`/`HashFunction`
/// seam — independently of the Foundation adapter — and that the adapter
/// `TLSKeySchedule` (which delegates to the same core) agrees with the core path.
///
/// This is the explicit byte-level oracle required by the crypto-seam slice:
/// known RFC 8448 secrets derived via the new generic path equal both the RFC
/// hex and the adapter output (no weakening of existing crypto tests).

import Testing
import Foundation
import Crypto
import P2PCoreBytes
import TLSWireCore
import TLSCryptoCore
@testable import TLSCore

@Suite("TLS Key Schedule Seam Differential Tests")
struct TLSKeyScheduleSeamDifferentialTests {

    // MARK: - RFC 8448 Section 3 known values (Simple 1-RTT Handshake)

    private let earlySecretHex = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    private let clientPrivateKeyHex = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
    private let serverPrivateKeyHex = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
    private let sharedSecretHex = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    private let chShTranscriptHashHex = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    private let clientHSSecretHex = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
    private let serverHSSecretHex = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"

    // MARK: - Hex helpers

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func bytesFromHex(_ string: String) -> [UInt8] {
        var out = [UInt8]()
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            if let byte = UInt8(string[index..<next], radix: 16) { out.append(byte) }
            index = next
        }
        return out
    }

    private func reconstructedSharedSecret() throws -> [UInt8] {
        let clientPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(bytesFromHex(clientPrivateKeyHex)))
        let serverPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(bytesFromHex(serverPrivateKeyHex)))
        let shared = try clientPriv.sharedSecretFromKeyAgreement(with: serverPriv.publicKey)
        return shared.withUnsafeBytes { [UInt8]($0) }
    }

    // MARK: - Core path == RFC 8448 (byte-for-byte through the seam)

    @Test("Core early secret equals RFC 8448 Section 3 (seam path)")
    func coreEarlySecretMatchesRFC() throws {
        var ks = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        ks.deriveEarlySecret(psk: nil)
        let earlySecret = try ks.currentEarlySecret()
        #expect(hex(earlySecret) == earlySecretHex)
    }

    @Test("Core handshake traffic secrets equal RFC 8448 Section 3 (seam path)")
    func coreHandshakeSecretsMatchRFC() throws {
        let shared = try reconstructedSharedSecret()
        #expect(hex(shared) == sharedSecretHex)

        var ks = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        ks.deriveEarlySecret(psk: nil)
        let transcriptHash = bytesFromHex(chShTranscriptHashHex)

        let (clientHS, serverHS) = try ks.deriveHandshakeSecrets(
            sharedSecret: shared,
            transcriptHash: transcriptHash
        )
        #expect(hex(clientHS) == clientHSSecretHex)
        #expect(hex(serverHS) == serverHSSecretHex)
    }

    // MARK: - Core path == adapter path (differential)

    @Test("Adapter handshake secrets equal the generic core path")
    func adapterMatchesCoreHandshake() throws {
        let shared = try reconstructedSharedSecret()
        let transcriptHash = bytesFromHex(chShTranscriptHashHex)

        // Generic core path
        var core = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        core.deriveEarlySecret(psk: nil)
        let (coreClient, coreServer) = try core.deriveHandshakeSecrets(
            sharedSecret: shared, transcriptHash: transcriptHash)

        // Adapter path
        var adapter = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        adapter.deriveEarlySecret(psk: nil)
        let (adClient, adServer) = try adapter.deriveHandshakeSecrets(
            sharedSecret: KeyExchangeSecret(rawRepresentation: Data(shared)),
            transcriptHash: Data(transcriptHash))

        #expect([UInt8](adClient.withUnsafeBytes { Data($0) }) == coreClient)
        #expect([UInt8](adServer.withUnsafeBytes { Data($0) }) == coreServer)
    }

    @Test("Adapter application secrets equal the generic core path")
    func adapterMatchesCoreApplication() throws {
        let shared = try reconstructedSharedSecret()
        let hsHash = bytesFromHex(chShTranscriptHashHex)
        let appHash = [UInt8](SHA256.hash(data: Data("CH||SH||EE||CT||CV||SF".utf8)))

        var core = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        core.deriveEarlySecret(psk: nil)
        _ = try core.deriveHandshakeSecrets(sharedSecret: shared, transcriptHash: hsHash)
        let (coreAppC, coreAppS) = try core.deriveApplicationSecrets(transcriptHash: appHash)

        var adapter = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        adapter.deriveEarlySecret(psk: nil)
        _ = try adapter.deriveHandshakeSecrets(
            sharedSecret: KeyExchangeSecret(rawRepresentation: Data(shared)),
            transcriptHash: Data(hsHash))
        let (adAppC, adAppS) = try adapter.deriveApplicationSecrets(transcriptHash: Data(appHash))

        #expect([UInt8](adAppC.withUnsafeBytes { Data($0) }) == coreAppC)
        #expect([UInt8](adAppS.withUnsafeBytes { Data($0) }) == coreAppS)
    }

    @Test("Finished verify data agrees between core and adapter (SHA-256 + SHA-384)")
    func finishedVerifyDataMatches() throws {
        let baseKey256 = [UInt8](repeating: 0x55, count: 32)
        let transcript256 = [UInt8](SHA256.hash(data: Data("handshake messages".utf8)))

        let core256 = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        let coreKey256 = try core256.finishedKey(from: baseKey256)
        let coreVerify256 = core256.finishedVerifyData(forKey: coreKey256, transcriptHash: transcript256)

        let adapter256 = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        let adKey256 = adapter256.finishedKey(from: SymmetricKey(data: Data(baseKey256)))
        let adVerify256 = adapter256.finishedVerifyData(
            forKey: adKey256, transcriptHash: Data(transcript256))

        #expect([UInt8](adKey256.withUnsafeBytes { Data($0) }) == coreKey256)
        #expect([UInt8](adVerify256) == coreVerify256)

        // SHA-384 suite
        let baseKey384 = [UInt8](repeating: 0x66, count: 48)
        let transcript384 = [UInt8](SHA384.hash(data: Data("handshake messages".utf8)))

        let core384 = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_256_gcm_sha384)
        let coreKey384 = try core384.finishedKey(from: baseKey384)
        let coreVerify384 = core384.finishedVerifyData(forKey: coreKey384, transcriptHash: transcript384)

        let adapter384 = TLSKeySchedule(cipherSuite: .tls_aes_256_gcm_sha384)
        let adKey384 = adapter384.finishedKey(from: SymmetricKey(data: Data(baseKey384)))
        let adVerify384 = adapter384.finishedVerifyData(
            forKey: adKey384, transcriptHash: Data(transcript384))

        #expect([UInt8](adKey384.withUnsafeBytes { Data($0) }) == coreKey384)
        #expect([UInt8](adVerify384) == coreVerify384)
        #expect(coreVerify384.count == 48)
    }

    @Test("Traffic keys agree between core and adapter")
    func trafficKeysMatch() throws {
        let secret = [UInt8](repeating: 0x42, count: 32)

        let coreKeys = try TLSTrafficKeys.derive(
            secret: secret.span,
            cipherSuite: .tls_aes_128_gcm_sha256,
            provider: TLSProvider.self)

        let adapterKeys = TrafficKeys(
            secret: SymmetricKey(data: Data(secret)),
            cipherSuite: .tls_aes_128_gcm_sha256)

        #expect([UInt8](adapterKeys.key.withUnsafeBytes { Data($0) }) == coreKeys.key)
        #expect([UInt8](adapterKeys.iv) == coreKeys.iv)
        #expect(coreKeys.key.count == 16)
        #expect(coreKeys.iv.count == 12)
    }

    @Test("Transcript hash agrees between core and adapter and equals direct SHA-256")
    func transcriptHashMatches() throws {
        let m1 = [UInt8]([0x01, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD])
        let m2 = [UInt8]([0x02, 0x00, 0x00, 0x02, 0x11, 0x22])

        var core = TLSCryptoCore.TLSTranscriptHash<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        core.update(with: m1.span)
        core.update(with: m2.span)
        let coreHash = core.currentHash()

        var adapter = TranscriptHash(cipherSuite: .tls_aes_128_gcm_sha256)
        adapter.update(with: Data(m1))
        adapter.update(with: Data(m2))
        let adapterHash = [UInt8](adapter.currentHash())

        let direct = [UInt8](SHA256.hash(data: Data(m1 + m2)))

        #expect(coreHash == direct)
        #expect(adapterHash == coreHash)
    }

    @Test("Empty transcript hash via core equals SHA-256 of empty string")
    func emptyTranscriptHashMatches() {
        let core = TLSCryptoCore.TLSTranscriptHash<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        let hashValue = core.currentHash()
        #expect(hex(hashValue) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("Exporter keying material agrees between core and adapter")
    func exporterKeyingMaterialMatches() throws {
        let shared = try reconstructedSharedSecret()
        let hsHash = [UInt8](repeating: 0xAA, count: 32)
        let appHash = [UInt8](repeating: 0xBB, count: 32)

        var core = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: .tls_aes_128_gcm_sha256)
        core.deriveEarlySecret(psk: nil)
        _ = try core.deriveHandshakeSecrets(sharedSecret: shared, transcriptHash: hsHash)
        _ = try core.deriveApplicationSecrets(transcriptHash: appHash)
        let coreEMS = try core.deriveExporterMasterSecret(transcriptHash: appHash)
        let coreEKM = try core.exportKeyingMaterial(
            exporterMasterSecret: coreEMS, label: "test-label",
            context: [0x01, 0x02, 0x03], length: 32)

        var adapter = TLSKeySchedule(cipherSuite: .tls_aes_128_gcm_sha256)
        adapter.deriveEarlySecret(psk: nil)
        _ = try adapter.deriveHandshakeSecrets(
            sharedSecret: KeyExchangeSecret(rawRepresentation: Data(shared)),
            transcriptHash: Data(hsHash))
        _ = try adapter.deriveApplicationSecrets(transcriptHash: Data(appHash))
        let adEMS = try adapter.deriveExporterMasterSecret(transcriptHash: Data(appHash))
        let adEKM = [UInt8](adapter.exportKeyingMaterial(
            exporterMasterSecret: adEMS, label: "test-label",
            context: Data([0x01, 0x02, 0x03]), length: 32))

        #expect([UInt8](adEMS.withUnsafeBytes { Data($0) }) == coreEMS)
        #expect(adEKM == coreEKM)
        #expect(coreEKM.count == 32)
    }
}
