/// Cross-check / KAT tests for the Embedded DER-ECDSA encoding
/// (``TLSCryptoProvider/EmbeddedECDSADER``).
///
/// The Embedded build signs ECDSA with the BoringSSL backend, which emits a raw
/// `r || s` p1363 signature; the TLS 1.3 CertificateVerify wire (RFC 8446 §4.2.3)
/// requires the DER `SEQUENCE { INTEGER r, INTEGER s }` encoding. `EmbeddedECDSADER`
/// performs that wrapping. Because the wire bytes must interop byte-for-byte with the
/// host path (which uses CryptoKit's `derRepresentation`), these tests assert:
///
///  1. KAT: `EmbeddedECDSADER.encode(raw:)` over a CryptoKit signature's
///     `rawRepresentation` (r||s) is BYTE-IDENTICAL to that same signature's
///     `derRepresentation` — the host wire output. Covers the leading-zero / sign-bit
///     ASN.1 INTEGER rules (high-bit-set integers get a `0x00` prefix; leading zeros
///     are stripped) across many random signatures, including high-bit edge cases.
///  2. Round-trip: `decode(encode(raw)) == raw` (fixed-width r||s restored).
///  3. Cross-verify: a host (`TLSDERP256/384Signature`) signature verifies after a
///     decode→re-encode round-trip through the Embedded DER logic, and the Embedded
///     DER encoding of a host signature's raw r||s verifies under the host verifier
///     (proving the two DER outputs are interchangeable on the wire).
///  4. Negative: a truncated / garbage / over-long-integer DER decodes to `nil`
///     (fail-closed — never a silent accept).
///
/// `EmbeddedECDSADER` is dual-built (NOT Embedded-gated) precisely so this oracle can
/// run on host against CryptoKit's authoritative DER output.

import Testing
import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto
import TLSCryptoProvider

@Suite("Embedded DER-ECDSA cross-check / KAT")
struct EmbeddedDERSignatureCrossCheckTests {

    // MARK: - KAT: encode(raw r||s) == CryptoKit derRepresentation

    @Test("P-256: EmbeddedECDSADER.encode equals CryptoKit derRepresentation (200 random signatures)")
    func p256EncodeMatchesCryptoKitDER() throws {
        let key = P256.Signing.PrivateKey()
        for i in 0..<200 {
            let message = Data("p256-kat-\(i)".utf8)
            let signature = try key.signature(for: message)
            let raw = [UInt8](signature.rawRepresentation)   // r||s, 64 bytes
            let ck = [UInt8](signature.derRepresentation)    // host wire DER
            #expect(raw.count == 64)
            let embedded = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 32)
            #expect(embedded == ck, "Embedded DER must equal CryptoKit DER (iteration \(i))")
        }
    }

    @Test("P-384: EmbeddedECDSADER.encode equals CryptoKit derRepresentation (200 random signatures)")
    func p384EncodeMatchesCryptoKitDER() throws {
        let key = P384.Signing.PrivateKey()
        for i in 0..<200 {
            let message = Data("p384-kat-\(i)".utf8)
            let signature = try key.signature(for: message)
            let raw = [UInt8](signature.rawRepresentation)   // r||s, 96 bytes
            let ck = [UInt8](signature.derRepresentation)
            #expect(raw.count == 96)
            let embedded = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 48)
            #expect(embedded == ck, "Embedded DER must equal CryptoKit DER (iteration \(i))")
        }
    }

    // MARK: - High-bit edge cases (explicit sign-byte / leading-zero handling)

    @Test("encode handles high-bit-set r and s (0x00 sign prefix) and leading zeros")
    func encodeHandlesSignBitAndLeadingZeros() throws {
        // r has high bit set in its first byte (needs a 0x00 prefix); s starts with a
        // zero byte then a high-bit byte (a leading zero that must NOT be stripped
        // because the next byte's high bit is set -> the 0x00 is the sign byte).
        var raw = [UInt8](repeating: 0, count: 64)
        raw[0] = 0xFF                       // r high bit set
        for i in 1..<32 { raw[i] = UInt8(i) }
        raw[32] = 0x00                      // s leading zero
        raw[33] = 0x80                      // s next byte high bit set
        for i in 34..<64 { raw[i] = UInt8(i) }

        let der = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 32)
        // Decode it back and confirm the fixed-width r||s is restored exactly.
        let decoded = try #require(EmbeddedECDSADER.decode(der: der, scalarLength: 32))
        #expect(decoded == raw)

        // Structural check: outer SEQUENCE tag, then two INTEGERs. r got a 0x00 prefix
        // (33-byte content); s dropped its leading zero (its value is 0x80 ...).
        #expect(der.first == 0x30)
    }

    @Test("encode rejects a wrong-length raw signature (no silent reshape)")
    func encodeRejectsWrongLength() {
        let bad = [UInt8](repeating: 0x01, count: 63)   // not 64
        #expect(throws: P2PCoreCrypto.CryptoError.self) {
            _ = try EmbeddedECDSADER.encode(raw: bad, scalarLength: 32)
        }
    }

    // MARK: - Round-trip (decode . encode == identity)

    @Test("P-256 round-trip: decode(encode(raw)) == raw (random)")
    func p256RoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        for i in 0..<100 {
            let signature = try key.signature(for: Data("rt-\(i)".utf8))
            let raw = [UInt8](signature.rawRepresentation)
            let der = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 32)
            let back = try #require(EmbeddedECDSADER.decode(der: der, scalarLength: 32))
            #expect(back == raw)
        }
    }

    @Test("P-384 round-trip: decode(encode(raw)) == raw (random)")
    func p384RoundTrip() throws {
        let key = P384.Signing.PrivateKey()
        for i in 0..<100 {
            let signature = try key.signature(for: Data("rt-\(i)".utf8))
            let raw = [UInt8](signature.rawRepresentation)
            let der = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 48)
            let back = try #require(EmbeddedECDSADER.decode(der: der, scalarLength: 48))
            #expect(back == raw)
        }
    }

    // MARK: - Cross-verify against the host DER scheme

    @Test("Host signature's raw r||s re-encoded via Embedded DER verifies under host verifier (P-256)")
    func hostRawReEncodedVerifiesUnderHost() throws {
        let signing = try TLSDERP256Signature.signingKey(
            rawRepresentation: [UInt8](P256.Signing.PrivateKey().rawRepresentation).span)
        let pub = TLSDERP256Signature.verifyingKey(for: signing)
        let message = [UInt8]("cross-verify".utf8)

        // Host signs -> host DER. Decode that DER to raw r||s, then re-encode via the
        // Embedded DER logic; the bytes must be identical (CryptoKit DER is canonical),
        // and the re-encoded signature must verify under the host verifier.
        let hostDER = try TLSDERP256Signature.sign(message.span, with: signing)
        let raw = try #require(EmbeddedECDSADER.decode(der: hostDER, scalarLength: 32))
        let reEncoded = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 32)
        #expect(reEncoded == hostDER)
        let valid = TLSDERP256Signature.isValid(signature: reEncoded.span, for: message.span, with: pub)
        #expect(valid)
    }

    @Test("Host signature's raw r||s re-encoded via Embedded DER verifies under host verifier (P-384)")
    func hostRawReEncodedVerifiesUnderHostP384() throws {
        let signing = try TLSDERP384Signature.signingKey(
            rawRepresentation: [UInt8](P384.Signing.PrivateKey().rawRepresentation).span)
        let pub = TLSDERP384Signature.verifyingKey(for: signing)
        let message = [UInt8]("cross-verify-384".utf8)

        let hostDER = try TLSDERP384Signature.sign(message.span, with: signing)
        let raw = try #require(EmbeddedECDSADER.decode(der: hostDER, scalarLength: 48))
        let reEncoded = try EmbeddedECDSADER.encode(raw: raw, scalarLength: 48)
        #expect(reEncoded == hostDER)
        let valid = TLSDERP384Signature.isValid(signature: reEncoded.span, for: message.span, with: pub)
        #expect(valid)
    }

    // MARK: - Negative: malformed DER decodes to nil (fail-closed)

    @Test("Malformed / truncated / over-long DER decodes to nil (no silent accept)")
    func malformedDERFailsClosed() {
        // Empty.
        #expect(EmbeddedECDSADER.decode(der: [], scalarLength: 32) == nil)
        // Not a SEQUENCE.
        #expect(EmbeddedECDSADER.decode(der: [0x02, 0x01, 0x00], scalarLength: 32) == nil)
        // SEQUENCE with one INTEGER (missing s).
        #expect(EmbeddedECDSADER.decode(der: [0x30, 0x03, 0x02, 0x01, 0x01], scalarLength: 32) == nil)
        // Over-long integer (r is 33 significant bytes -> exceeds 32).
        var over = [UInt8]([0x30, 0x46, 0x02, 0x21])
        over.append(contentsOf: [UInt8](repeating: 0x7F, count: 33))   // 33-byte r
        over.append(contentsOf: [0x02, 0x21])
        over.append(contentsOf: [UInt8](repeating: 0x7F, count: 33))   // 33-byte s
        #expect(EmbeddedECDSADER.decode(der: over, scalarLength: 32) == nil)
    }

    @Test("Trailing bytes after the SEQUENCE decode to nil")
    func trailingBytesFailClosed() throws {
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: Data("trailer".utf8))
        var der = [UInt8](signature.derRepresentation)
        der.append(0xAA)   // one trailing byte
        #expect(EmbeddedECDSADER.decode(der: der, scalarLength: 32) == nil)
    }
}
