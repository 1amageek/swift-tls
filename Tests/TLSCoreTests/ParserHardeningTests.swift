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
}
