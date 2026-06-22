/// DTLS HelloVerifyRequest (RFC 6347 Section 4.2.1)
///
/// DTLS-specific message for cookie-based DoS protection.
///
/// struct {
///   ProtocolVersion server_version;
///   opaque cookie<0..2^8-1>;
/// } HelloVerifyRequest;

import Foundation
import Crypto
import TLSCore

/// DTLS HelloVerifyRequest message
public struct HelloVerifyRequest: Sendable {
    /// Server protocol version
    public let serverVersion: DTLSVersion

    /// Cookie for DoS protection
    public let cookie: Data

    public init(
        serverVersion: DTLSVersion = .v1_2,
        cookie: Data
    ) {
        self.serverVersion = serverVersion
        self.cookie = cookie
    }

    /// Build the cookie binding material for a ClientHello.
    ///
    /// RFC 6347 §4.2.1 requires the cookie to be bound to the client's transport
    /// address; a robust server also binds it to the ClientHello contents so that a
    /// cookie minted for one ClientHello cannot be replayed with a different one.
    /// We cover `clientAddress || client_random || cipher_suites`.
    ///
    /// - Parameters:
    ///   - clientAddress: Client's network address (IP:port)
    ///   - clientRandom: The 32-byte ClientHello random
    ///   - cipherSuites: The offered cipher suites
    /// - Returns: Concatenated binding material fed to the cookie HMAC
    public static func bindingMaterial(
        clientAddress: Data,
        clientRandom: Data,
        cipherSuites: [DTLSCipherSuite]
    ) -> Data {
        var writer = TLSWriter()
        writer.writeVector16(clientAddress)
        writer.writeVector8(clientRandom)
        var suitesWriter = TLSWriter()
        for suite in cipherSuites {
            suite.encode(writer: &suitesWriter)
        }
        writer.writeVector16(suitesWriter.finish())
        return writer.finish()
    }

    /// Generate a cookie bound to the ClientHello using the provided secret provider.
    /// - Parameters:
    ///   - clientAddress: Client's network address (IP:port)
    ///   - clientHello: The ClientHello whose contents the cookie is bound to
    ///   - provider: The process-global rotating cookie secret provider
    /// - Returns: A HelloVerifyRequest with a computed, ClientHello-bound cookie
    public static func generate(
        clientAddress: Data,
        clientHello: DTLSClientHello,
        provider: DTLSCookieSecretProvider
    ) -> HelloVerifyRequest {
        let material = bindingMaterial(
            clientAddress: clientAddress,
            clientRandom: clientHello.random,
            cipherSuites: clientHello.cipherSuites
        )
        let cookie = provider.makeCookie(bindingMaterial: material)
        return HelloVerifyRequest(cookie: cookie)
    }

    /// Verify a cookie bound to the ClientHello.
    /// - Parameters:
    ///   - cookie: The cookie presented by the client
    ///   - clientAddress: Client's network address
    ///   - clientHello: The ClientHello whose contents the cookie must be bound to
    ///   - provider: The process-global rotating cookie secret provider
    /// - Returns: True if the cookie is valid for this ClientHello and address
    public static func verifyCookie(
        _ cookie: Data,
        clientAddress: Data,
        clientHello: DTLSClientHello,
        provider: DTLSCookieSecretProvider
    ) -> Bool {
        let material = bindingMaterial(
            clientAddress: clientAddress,
            clientRandom: clientHello.random,
            cipherSuites: clientHello.cipherSuites
        )
        return provider.verifyCookie(cookie, bindingMaterial: material)
    }

    /// Encode the HelloVerifyRequest body
    public func encode() -> Data {
        var writer = TLSWriter()
        serverVersion.encode(writer: &writer)
        writer.writeVector8(cookie)
        return writer.finish()
    }

    /// Decode a HelloVerifyRequest from body data
    public static func decode(from data: Data) throws -> HelloVerifyRequest {
        var reader = TLSReader(data: data)
        let version = try DTLSVersion.decode(reader: &reader)
        let cookie = try reader.readVector8()
        return HelloVerifyRequest(serverVersion: version, cookie: cookie)
    }
}
