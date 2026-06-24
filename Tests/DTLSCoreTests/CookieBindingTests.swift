/// DTLS Cookie Binding Tests (RFC 6347 §4.2.1)
///
/// Verifies that:
/// - The HelloVerifyRequest cookie is bound to the ClientHello contents (a swapped
///   ClientHello fails verification).
/// - A non-empty cookie that cannot be validated is always rejected (never silently
///   accepted) because the cookie secret is process-global.
/// - The legitimate cookie exchange still completes.

import Foundation
import Testing
import DTLSWireCore
import TLSWireCore
import Crypto
import TLSCore
@testable import DTLSCore

@Suite("DTLS Cookie Binding")
struct CookieBindingTests {

    private func encodeClientHello(_ ch: DTLSClientHello, messageSeq: UInt16 = 0) -> Data {
        DTLSHandshakeHeader.encodeMessage(
            type: .clientHello,
            messageSeq: messageSeq,
            body: ch.encode()
        )
    }

    private func extractHVRCookie(_ actions: [DTLSHandshakeAction]) throws -> Data {
        guard case .sendMessage(let hvrMsg) = actions.first else {
            throw DTLSError.handshakeFailed("No HelloVerifyRequest")
        }
        var reader = TLSReader(data: hvrMsg)
        _ = try DTLSHandshakeHeader.decode(reader: &reader)
        let body = Data(try reader.readBytes(reader.remaining))
        return try HelloVerifyRequest.decode(from: body).cookie
    }

    // MARK: - Binding

    @Test("Cookie minted for one ClientHello fails when presented with a different ClientHello")
    func cookieIsBoundToClientHello() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        // Each handler uses its own provider so rotation/state is isolated per test.
        let provider = DTLSCookieSecretProvider()
        let server = DTLSServerHandshakeHandler(certificate: cert, cookieProvider: provider)

        let addr = Data([192, 168, 1, 1])

        // ClientHello A → server issues a cookie bound to A.
        let helloA = try DTLSClientHello(cipherSuites: [.ecdheEcdsaWithAes128GcmSha256])
        let hvrActions = try server.processClientHello(encodeClientHello(helloA), clientAddress: addr)
        let cookie = try extractHVRCookie(hvrActions)
        #expect(!cookie.isEmpty)

        // A different ClientHello B (different random) carrying A's cookie must fail:
        // the cookie is bound to A's contents.
        let helloB = try DTLSClientHello(
            cookie: cookie,
            cipherSuites: [.ecdheEcdsaWithAes128GcmSha256]
        )
        #expect(helloB.random != helloA.random)

        let serverB = DTLSServerHandshakeHandler(certificate: cert, cookieProvider: provider)
        #expect(throws: DTLSError.self) {
            _ = try serverB.processClientHello(encodeClientHello(helloB), clientAddress: addr)
        }

        // The SAME ClientHello A replayed with its own cookie verifies successfully.
        let helloAWithCookie = try DTLSClientHello(
            random: helloA.random,
            cookie: cookie,
            cipherSuites: helloA.cipherSuites
        )
        let serverC = DTLSServerHandshakeHandler(certificate: cert, cookieProvider: provider)
        let flight = try serverC.processClientHello(encodeClientHello(helloAWithCookie), clientAddress: addr)
        #expect(!flight.isEmpty, "A correctly-bound cookie should advance the handshake")
        #expect(serverC.currentState == .waitingClientKeyExchange)
    }

    @Test("A presented-but-unverifiable cookie is always rejected")
    func presentedButUnverifiableCookieRejected() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let provider = DTLSCookieSecretProvider()
        // Fresh server that never issued this cookie. Because the secret is
        // process-global, the server still validates (and rejects) the cookie
        // rather than proceeding without validation.
        let server = DTLSServerHandshakeHandler(certificate: cert, cookieProvider: provider)

        let bogusCookie = Data(repeating: 0x5A, count: 32)
        let hello = try DTLSClientHello(
            cookie: bogusCookie,
            cipherSuites: [.ecdheEcdsaWithAes128GcmSha256]
        )

        #expect(throws: DTLSError.self) {
            _ = try server.processClientHello(encodeClientHello(hello), clientAddress: Data([10, 0, 0, 1]))
        }
        #expect(server.currentState != .waitingClientKeyExchange,
                "Server must not proceed on an unverifiable cookie")
    }

    @Test("Cookie verification is bound to the client address")
    func cookieBoundToAddress() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let provider = DTLSCookieSecretProvider()
        let server = DTLSServerHandshakeHandler(certificate: cert, cookieProvider: provider)

        let addrA = Data([192, 168, 1, 1])
        let addrB = Data([10, 0, 0, 1])

        let hello = try DTLSClientHello(cipherSuites: [.ecdheEcdsaWithAes128GcmSha256])
        let cookie = try extractHVRCookie(
            try server.processClientHello(encodeClientHello(hello), clientAddress: addrA)
        )

        let helloWithCookie = try DTLSClientHello(
            random: hello.random,
            cookie: cookie,
            cipherSuites: hello.cipherSuites
        )

        // Same cookie + same ClientHello but a DIFFERENT address must fail.
        let server2 = DTLSServerHandshakeHandler(certificate: cert, cookieProvider: provider)
        #expect(throws: DTLSError.self) {
            _ = try server2.processClientHello(encodeClientHello(helloWithCookie), clientAddress: addrB)
        }
    }

    @Test("Provider verifies cookies it minted and rejects forgeries")
    func providerRoundTrip() {
        let provider = DTLSCookieSecretProvider()
        let material = Data("client-hello-binding".utf8)
        let cookie = provider.makeCookie(bindingMaterial: material)

        #expect(provider.verifyCookie(cookie, bindingMaterial: material))
        #expect(!provider.verifyCookie(cookie, bindingMaterial: Data("different".utf8)))
        #expect(!provider.verifyCookie(Data(repeating: 0x00, count: cookie.count), bindingMaterial: material))
    }
}
