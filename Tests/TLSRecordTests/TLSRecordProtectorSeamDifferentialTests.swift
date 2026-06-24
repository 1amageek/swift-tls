/// Byte-level differential tests for the seam-routed TLS 1.3 record AEAD.
///
/// Asserts that the Embedded-clean `TLSRecordCore.TLSRecordProtector<C, A>`
/// specialised at `C = TLSCryptoProvider`, `A = TLSRecordAEAD` produces
/// byte-for-byte the same ciphertext as the adapter `TLSRecordCryptor` (the
/// public path the existing suite exercises), and that a tampered tag is rejected
/// with `badRecordMac` (never accepted, never a garbage plaintext — RFC 8446 §5.2,
/// padding-oracle prevention).
///
/// This is the explicit byte-level oracle required by the record-AEAD crypto-seam
/// slice: a known record encrypted via the new generic path equals both the
/// adapter output and a fixed expected ciphertext.

import Testing
import Foundation
import Crypto
import P2PCoreBytes

@testable import TLSRecord
@testable import TLSCore
import TLSRecordCore

@Suite("TLS Record Protector Seam Differential Tests")
struct TLSRecordProtectorSeamDifferentialTests {

    private typealias CoreProtector = TLSRecordProtector<TLSCryptoProvider, TLSRecordAEAD>

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Derives one direction's traffic keys deterministically from a fixed secret,
    /// returning both the adapter `TrafficKeys` and the raw key/iv bytes so the
    /// generic core path and the adapter path use identical key material.
    private func keys(
        secretByte: UInt8,
        cipherSuite: CipherSuite
    ) -> (TrafficKeys, key: [UInt8], iv: [UInt8]) {
        let secret = SymmetricKey(data: Data(repeating: secretByte, count: cipherSuite.hashLength))
        let traffic = TrafficKeys(secret: secret, cipherSuite: cipherSuite)
        let key = [UInt8](traffic.key.withUnsafeBytes { Data($0) })
        let iv = [UInt8](traffic.iv)
        return (traffic, key, iv)
    }

    // MARK: - Core ciphertext == adapter ciphertext (byte-for-byte)

    @Test("Core seal equals adapter encrypt byte-for-byte (all suites, multiple seqs)",
          arguments: [
            CipherSuite.tls_aes_128_gcm_sha256,
            CipherSuite.tls_aes_256_gcm_sha384,
            CipherSuite.tls_chacha20_poly1305_sha256,
          ])
    func coreSealEqualsAdapter(cipherSuite: CipherSuite) throws {
        let (sendTraffic, sendKey, sendIV) = keys(secretByte: 0x2b, cipherSuite: cipherSuite)
        let (recvTraffic, _, _) = keys(secretByte: 0x4d, cipherSuite: cipherSuite)

        // Adapter path: install keys, encrypt records 0..2 (seq advances internally).
        let cryptor = TLSRecordCryptor(cipherSuite: cipherSuite)
        try cryptor.updateSendKeys(sendTraffic)
        try cryptor.updateReceiveKeys(recvTraffic)

        // Generic core path: single-direction send protector built from the same
        // key/iv; sequence number is threaded in by the caller (test).
        let coreSend = try CoreProtector(
            aead: TLSRecordAEAD(key: sendKey, cipherSuite: cipherSuite),
            iv: sendIV
        )

        for seq in UInt64(0)..<3 {
            let content = Data([0x14, UInt8(seq), 0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
            let adapterCT = try cryptor.encrypt(content: content, type: .handshake)
            let coreCT = try coreSend.protect(
                content: [UInt8](content), type: .handshake, sequenceNumber: seq)
            #expect([UInt8](adapterCT) == coreCT,
                    "suite=\(cipherSuite) seq=\(seq): adapter=\(hex([UInt8](adapterCT))) core=\(hex(coreCT))")
        }
    }

    // MARK: - Round-trip through the generic core

    @Test("Core protect/unprotect round-trips and recovers content type")
    func coreRoundTrip() throws {
        let suite = CipherSuite.tls_aes_128_gcm_sha256
        let (_, key, iv) = keys(secretByte: 0x77, cipherSuite: suite)
        let protector = try CoreProtector(aead: TLSRecordAEAD(key: key, cipherSuite: suite), iv: iv)

        let content: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05]
        let ct = try protector.protect(content: content, type: .applicationData, sequenceNumber: 7)
        let (recovered, type) = try protector.unprotect(ciphertext: ct, sequenceNumber: 7)
        #expect(recovered == content)
        #expect(type == .applicationData)
    }

    // MARK: - Adapter encrypt -> core unprotect cross-acceptance

    @Test("Adapter ciphertext decrypts via the generic core path")
    func adapterCiphertextOpensViaCore() throws {
        let suite = CipherSuite.tls_chacha20_poly1305_sha256
        let (sendTraffic, sendKey, sendIV) = keys(secretByte: 0x31, cipherSuite: suite)
        let (recvTraffic, _, _) = keys(secretByte: 0x32, cipherSuite: suite)

        let cryptor = TLSRecordCryptor(cipherSuite: suite)
        try cryptor.updateSendKeys(sendTraffic)
        try cryptor.updateReceiveKeys(recvTraffic)

        let content = Data("hello tls record".utf8)
        let adapterCT = try cryptor.encrypt(content: content, type: .applicationData)

        // The core read protector uses the SAME key/iv as the adapter's send side
        // (we built the send keys here), so it must open the adapter ciphertext.
        let coreRead = try CoreProtector(
            aead: TLSRecordAEAD(key: sendKey, cipherSuite: suite), iv: sendIV)
        let (recovered, type) = try coreRead.unprotect(
            ciphertext: [UInt8](adapterCT), sequenceNumber: 0)
        #expect(Data(recovered) == content)
        #expect(type == .applicationData)
    }

    // MARK: - Tamper rejection (no silent fallback)

    @Test("Tampered tag is rejected with badRecordMac, never accepted")
    func tamperedTagRejected() throws {
        let suite = CipherSuite.tls_aes_128_gcm_sha256
        let (_, key, iv) = keys(secretByte: 0x55, cipherSuite: suite)
        let protector = try CoreProtector(aead: TLSRecordAEAD(key: key, cipherSuite: suite), iv: iv)

        var ct = try protector.protect(
            content: [0x01, 0x02, 0x03], type: .applicationData, sequenceNumber: 0)
        // Flip a bit in the last (tag) byte.
        ct[ct.count - 1] ^= 0x01

        #expect(throws: TLSRecordProtectionError.badRecordMac) {
            _ = try protector.unprotect(ciphertext: ct, sequenceNumber: 0)
        }
    }

    @Test("Wrong sequence number is rejected with badRecordMac")
    func wrongSequenceRejected() throws {
        let suite = CipherSuite.tls_aes_256_gcm_sha384
        let (_, key, iv) = keys(secretByte: 0x66, cipherSuite: suite)
        let protector = try CoreProtector(aead: TLSRecordAEAD(key: key, cipherSuite: suite), iv: iv)

        let ct = try protector.protect(
            content: [0xAA, 0xBB], type: .applicationData, sequenceNumber: 3)
        #expect(throws: TLSRecordProtectionError.badRecordMac) {
            _ = try protector.unprotect(ciphertext: ct, sequenceNumber: 4)
        }
    }

    // MARK: - Fixed golden ciphertext (locks the byte output)

    @Test("Known key/iv/seq produces a stable ciphertext (golden)")
    func goldenCiphertext() throws {
        // Fixed inputs so the AEAD output is fully determined.
        let suite = CipherSuite.tls_aes_128_gcm_sha256
        let key = [UInt8](repeating: 0x01, count: 16)
        let iv = [UInt8](repeating: 0x02, count: 12)
        let protector = try CoreProtector(aead: TLSRecordAEAD(key: key, cipherSuite: suite), iv: iv)

        let content: [UInt8] = [0x68, 0x65, 0x6c, 0x6c, 0x6f] // "hello"
        let ct = try protector.protect(content: content, type: .handshake, sequenceNumber: 0)

        // Compute the same record directly with swift-crypto as an independent
        // oracle: nonce = iv (seq 0 leaves it unchanged), AAD = 0x17 0x0303 len.
        let inner = content + [TLSContentType.handshake.rawValue]
        let length = inner.count + 16
        let aad = Data([0x17, 0x03, 0x03, UInt8(length >> 8), UInt8(length & 0xFF)])
        let sealed = try AES.GCM.seal(
            Data(inner),
            using: SymmetricKey(data: Data(key)),
            nonce: try AES.GCM.Nonce(data: Data(iv)),
            authenticating: aad)
        let expected = [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)

        #expect(ct == expected, "core=\(hex(ct)) expected=\(hex(expected))")
        #expect(ct.count == inner.count + 16)
    }
}
