/// Parser Hardening Tests
///
/// Covers:
/// - KeyShare / SupportedVersions decoding from a SLICED `Data` (non-zero
///   startIndex) must not trap — parsers must be startIndex-relative.
/// - The client advertises only signature schemes it can actually verify (no RSA),
///   so the wire capability matches the real verification capability.

import Testing
import TLSWireCore
import Foundation
@testable import TLSCore

@Suite("Parser Hardening")
struct ParserHardeningTests {

    // MARK: - Sliced Data Decoding (RFC 8446 §4.2.8 / §4.2.1)

    @Test("KeyShareClientHello decodes from a sliced Data with non-zero startIndex")
    func keyShareDecodesFromSlicedData() throws {
        let entry = KeyShareEntry(
            group: .x25519,
            keyExchange: Data(repeating: 0xAB, count: 32)
        )
        let original = KeyShareClientHello(clientShares: [entry])
        let encoded = original.encode()

        // Prepend a byte and drop it: the resulting slice has startIndex == 1.
        var prefixed = Data([0xFF])
        prefixed.append(encoded)
        let sliced = prefixed.dropFirst()
        #expect(sliced.startIndex != 0)

        let decoded = try KeyShareClientHello.decode(from: sliced)
        #expect(decoded.clientShares.count == 1)
        #expect(decoded.clientShares[0].group == .x25519)
        #expect(decoded.clientShares[0].keyExchange == entry.keyExchange)
    }

    @Test("KeyShareExtension decodes with explicit context from a sliced Data")
    func keyShareExtensionDecodesWithContextFromSlicedData() throws {
        let entry = KeyShareEntry(group: .secp256r1, keyExchange: Data(repeating: 0x11, count: 65))
        let encoded = KeyShareServerHello(serverShare: entry).encode()

        let sliced = (Data([0x00, 0x00]) + encoded).dropFirst(2)
        #expect(sliced.startIndex != 0)

        let decoded = try KeyShareExtension.decode(from: sliced, context: .serverHello)
        guard case .serverHello(let sh) = decoded else {
            Issue.record("Expected serverHello variant")
            return
        }
        #expect(sh.serverShare.group == .secp256r1)
    }

    @Test("SupportedVersions decodes from a sliced Data with explicit context")
    func supportedVersionsDecodesFromSlicedData() throws {
        let client = SupportedVersionsClientHello(versions: [TLSConstants.version13])
        let encoded = client.encode()

        let sliced = (Data([0x7F]) + encoded).dropFirst()
        #expect(sliced.startIndex != 0)

        let decoded = try SupportedVersionsExtension.decode(from: sliced, context: .clientHello)
        guard case .clientHello(let ch) = decoded else {
            Issue.record("Expected clientHello variant")
            return
        }
        #expect(ch.supportsTLS13)
    }

    @Test("SupportedVersionsServerHello decodes from a sliced Data")
    func supportedVersionsServerHelloFromSlicedData() throws {
        let server = SupportedVersionsServerHello(selectedVersion: TLSConstants.version13)
        let encoded = server.encode()
        let sliced = (Data([0xAA, 0xBB, 0xCC]) + encoded).dropFirst(3)
        #expect(sliced.startIndex != 0)

        let decoded = try SupportedVersionsServerHello.decode(from: sliced)
        #expect(decoded.isTLS13)
    }

    // MARK: - Signature Scheme Advertisement (capability match)

    @Test("Client does not advertise RSA signature schemes it cannot verify")
    func clientDoesNotAdvertiseRSA() throws {
        let client = ClientStateMachine()
        let (clientHelloData, _) = try client.startHandshake(configuration: TLSConfiguration())

        // startHandshake returns the full handshake message (4-byte header + body);
        // strip the header before decoding the ClientHello body.
        let (type, body, _) = try HandshakeCodec.decodeMessage(from: clientHelloData)
        #expect(type == .clientHello)
        let clientHello = try ClientHello.decode(from: body)

        var advertised: [SignatureScheme] = []
        for ext in clientHello.extensions {
            if case .signatureAlgorithms(let sa) = ext {
                advertised = sa.supportedSignatureAlgorithms
            }
        }
        #expect(!advertised.isEmpty, "signature_algorithms must be present")

        let rsaSchemes: Set<SignatureScheme> = [
            .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512,
            .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512
        ]
        for scheme in advertised {
            #expect(!rsaSchemes.contains(scheme), "Must not advertise unsupported RSA scheme \(scheme)")
        }
        // The schemes we DO advertise must be exactly the verifiable set.
        #expect(Set(advertised) == Set(ClientStateMachine.advertisedSignatureSchemes))
    }

    @Test("Default signature_algorithms extension excludes RSA")
    func defaultSignatureAlgorithmsExcludesRSA() {
        let schemes = Set(SignatureAlgorithmsExtension.default.supportedSignatureAlgorithms)
        #expect(!schemes.contains(.rsa_pss_rsae_sha256))
        #expect(!schemes.contains(.rsa_pss_rsae_sha384))
        #expect(!schemes.contains(.rsa_pss_rsae_sha512))
        #expect(schemes.contains(.ecdsa_secp256r1_sha256))
    }

    // MARK: - ASN.1 DER Parser Hardening (ITU-T X.690)
    //
    // The local ASN1Parser is reached via OCSP / CRL revocation checking
    // (CertificateRevocation.swift), gated behind `revocationCheckMode`. Malformed
    // DER from a peer must produce a typed throw, never a runtime trap.

    @Test("ASN.1 long-form length that would overflow position+length throws, not traps")
    func asn1LongFormLengthOverflowThrows() {
        // SEQUENCE tag (0x30), then a long-form length: 0x88 says "8 length bytes
        // follow". The encoded length is exactly `Int.max` (0x7FFF...FF), which
        // PASSES `readLength`'s `length <= Int.max >> 8` cap (the final shift lands
        // at `Int.max` without overflowing the guard) — so it reaches the reordered
        // bounds guard `length <= data.endIndex - position`. With the old
        // `position + length` add that bounds check overflowed `Int` and trapped;
        // it must now throw `unexpectedEndOfData`. This genuinely exercises the
        // guard reorder (mirroring the swift-quic twin) rather than being caught by
        // the readLength cap.
        let malformed = Data([
            0x30,                                           // SEQUENCE
            0x88,                                           // long form, 8 length bytes
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // length == Int.max
        ])
        #expect(throws: ASN1Error.self) {
            _ = try ASN1Parser.parseOne(from: malformed)
        }
    }

    @Test("ASN.1 deeply-nested constructed TLVs throw at the depth cap, not stack-overflow")
    func asn1DeepNestingThrows() {
        // A chain of constructed SEQUENCEs each declaring a 1-byte body that is
        // itself another SEQUENCE: `30 01 30 01 30 01 …`. Nesting far past the cap
        // (64) would recurse unboundedly and overflow the stack without a limit.
        let nestingCount = 512
        var deeplyNested = Data()
        for _ in 0..<nestingCount {
            deeplyNested.append(contentsOf: [0x30, 0x01]) // SEQUENCE, length 1
        }
        // Innermost content byte (a NULL-ish placeholder) so the last length is satisfiable.
        deeplyNested.append(0x00)

        #expect(throws: ASN1Error.self) {
            _ = try ASN1Parser.parseOne(from: deeplyNested)
        }
    }

    @Test("ASN.1 well-formed nested structure within the depth cap still parses")
    func asn1WellFormedStructureParses() throws {
        // SEQUENCE { INTEGER 1, OCTET STRING "AB" } — a normal, shallow structure
        // representative of the TLVs OCSP/CRL parsing encounters.
        let inner = ASN1Builder.integer(1) + ASN1Builder.octetString(Data([0x41, 0x42]))
        let der = ASN1Builder.sequence([inner])

        let value = try ASN1Parser.parseOne(from: der)
        #expect(value.tag.tagNumber == ASN1Tag.sequence.tagNumber)
        #expect(value.children.count == 2)
        #expect(value.children[0].tag.tagNumber == ASN1Tag.integer.tagNumber)
        #expect(value.children[1].tag.tagNumber == ASN1Tag.octetString.tagNumber)
        #expect(value.children[1].content == Data([0x41, 0x42]))
    }

    @Test("ASN.1 nesting exactly at the depth cap parses; one deeper throws")
    func asn1DepthCapBoundary() throws {
        // Build a chain of `maxDepth` nested SEQUENCEs wrapping a single INTEGER.
        // The root parse is depth 0, so `maxDepth` levels of nesting are accepted.
        func nest(_ payload: Data, times: Int) -> Data {
            var current = payload
            for _ in 0..<times {
                current = ASN1Builder.sequence([current])
            }
            return current
        }
        let leaf = ASN1Builder.integer(7)

        // `maxDepth` wrapping SEQUENCEs: the deepest child is parsed at depth == maxDepth.
        let atCap = nest(leaf, times: ASN1Parser.maxDepth)
        let parsed = try ASN1Parser.parseOne(from: atCap)
        #expect(parsed.tag.tagNumber == ASN1Tag.sequence.tagNumber)

        // One level deeper must be rejected at the cap.
        let pastCap = nest(leaf, times: ASN1Parser.maxDepth + 1)
        #expect(throws: ASN1Error.self) {
            _ = try ASN1Parser.parseOne(from: pastCap)
        }
    }
}
