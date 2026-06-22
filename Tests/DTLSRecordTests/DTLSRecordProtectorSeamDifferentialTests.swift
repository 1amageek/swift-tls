/// Byte-level differential tests for the seam-routed DTLS 1.2 record AEAD.
///
/// Asserts that the Embedded-clean `DTLSRecordCore.DTLSRecordProtector<C, A>`
/// specialised at `C = TLSFoundationProvider`, `A = DTLSRecordAEAD` produces
/// byte-for-byte the same output as the adapter `DTLSRecordCryptor` (the public
/// path the existing suite exercises), and that a tampered tag is rejected
/// (never accepted, never a garbage plaintext — RFC 6347 §4.1.2.7).

import Testing
import Foundation
import Crypto
import P2PCoreBytes

@testable import DTLSRecord
@testable import DTLSCore
import TLSCore
import DTLSRecordCore

@Suite("DTLS Record Protector Seam Differential Tests")
struct DTLSRecordProtectorSeamDifferentialTests {

    private typealias CoreProtector = DTLSRecordProtector<TLSFoundationProvider, DTLSRecordAEAD>

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Core output == adapter output (byte-for-byte)

    @Test("Core seal equals adapter seal byte-for-byte")
    func coreSealEqualsAdapter() throws {
        let keyBytes = [UInt8](repeating: 0x09, count: 16)
        let key = SymmetricKey(data: Data(keyBytes))
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let plaintext = Data("dtls application data".utf8)
        let aad = Data(repeating: 0xAB, count: 13)

        let adapter = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: key,
            fixedIV: fixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad)

        let core = try CoreProtector(aead: DTLSRecordAEAD(key: keyBytes), fixedIV: [UInt8](fixedIV))
        let coreOut = try core.seal(
            plaintext: [UInt8](plaintext),
            explicitNonce: [UInt8](explicitNonce),
            aad: [UInt8](aad))

        #expect([UInt8](adapter) == coreOut,
                "adapter=\(hex([UInt8](adapter))) core=\(hex(coreOut))")
    }

    // MARK: - Round-trip + cross-acceptance

    @Test("Core seal/open round-trips and adapter opens the core output")
    func coreRoundTripAndCrossAccept() throws {
        let keyBytes = [UInt8](repeating: 0x42, count: 16)
        let key = SymmetricKey(data: Data(keyBytes))
        let fixedIV = Data([0x10, 0x20, 0x30, 0x40])
        let explicitNonce = Data([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05])
        let plaintext = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let aad = Data(repeating: 0x7C, count: 13)

        let core = try CoreProtector(aead: DTLSRecordAEAD(key: keyBytes), fixedIV: [UInt8](fixedIV))
        let coreCT = try core.seal(
            plaintext: [UInt8](plaintext),
            explicitNonce: [UInt8](explicitNonce),
            aad: [UInt8](aad))

        // Core opens its own output.
        let coreOpened = try core.open(ciphertext: coreCT, aad: [UInt8](aad))
        #expect(coreOpened == [UInt8](plaintext))

        // Adapter opens the core output (cross-acceptance).
        let adapterOpened = try DTLSRecordCryptor.open(
            ciphertext: Data(coreCT), key: key, fixedIV: fixedIV, additionalData: aad)
        #expect(adapterOpened == plaintext)
    }

    // MARK: - Tamper rejection (no silent fallback)

    @Test("Tampered tag is rejected, never accepted")
    func tamperedTagRejected() throws {
        let keyBytes = [UInt8](repeating: 0x55, count: 16)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let aad = Data(repeating: 0x33, count: 13)

        let core = try CoreProtector(aead: DTLSRecordAEAD(key: keyBytes), fixedIV: [UInt8](fixedIV))
        var ct = try core.seal(
            plaintext: [0x01, 0x02, 0x03],
            explicitNonce: [UInt8](explicitNonce),
            aad: [UInt8](aad))
        ct[ct.count - 1] ^= 0x01 // flip a tag bit

        #expect(throws: DTLSRecordProtectionError.decryptionFailed) {
            _ = try core.open(ciphertext: ct, aad: [UInt8](aad))
        }
    }

    @Test("Wrong AAD is rejected, never accepted")
    func wrongAADRejected() throws {
        let keyBytes = [UInt8](repeating: 0x66, count: 16)
        let fixedIV = Data(repeating: 0x01, count: 4)
        let explicitNonce = Data(repeating: 0x02, count: 8)
        let aad = Data(repeating: 0x33, count: 13)
        let wrongAAD = Data(repeating: 0x44, count: 13)

        let core = try CoreProtector(aead: DTLSRecordAEAD(key: keyBytes), fixedIV: [UInt8](fixedIV))
        let ct = try core.seal(
            plaintext: [0x09, 0x08, 0x07],
            explicitNonce: [UInt8](explicitNonce),
            aad: [UInt8](aad))

        #expect(throws: DTLSRecordProtectionError.decryptionFailed) {
            _ = try core.open(ciphertext: ct, aad: [UInt8](wrongAAD))
        }
    }
}
