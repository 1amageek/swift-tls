/// DTLS HelloVerifyRequest (RFC 6347 Section 4.2.1)
///
/// DTLS-specific message for cookie-based DoS protection.
///
/// struct {
///   ProtocolVersion server_version;
///   opaque cookie<0..2^8-1>;
/// } HelloVerifyRequest;
///
/// This type stays in the Foundation adapter (not `DTLSWireCore`): its cookie is
/// surfaced as `Data` and its `generate` / `verifyCookie` helpers drive the
/// crypto-backed `DTLSCookieSecretProvider`. The pure wire framing is shared with
/// the core via the `DTLSWireCore` `ByteReader` / `ByteWriter` cursors.

import Foundation
import P2PCoreBytes
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
        var writer = ByteWriter()
        do {
            try writer.writeVector16([UInt8](clientAddress))
            try writer.writeVector8([UInt8](clientRandom))
            var suitesWriter = ByteWriter()
            for suite in cipherSuites {
                suite.encode(writer: &suitesWriter)
            }
            try writer.writeVector16(suitesWriter.finishArray())
        } catch {
            fatalError("DTLS cookie binding material exceeded a wire length bound: \(error)")
        }
        return Data(writer.finishArray())
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
            clientRandom: Data(clientHello.random),
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
            clientRandom: Data(clientHello.random),
            cipherSuites: clientHello.cipherSuites
        )
        return provider.verifyCookie(cookie, bindingMaterial: material)
    }

    /// Encode the HelloVerifyRequest body
    public func encode() -> Data {
        var writer = ByteWriter()
        serverVersion.encode(writer: &writer)
        do {
            try writer.writeVector8([UInt8](cookie))
        } catch {
            fatalError("DTLS HelloVerifyRequest encoding exceeded a wire length bound: \(error)")
        }
        return Data(writer.finishArray())
    }

    /// Decode a HelloVerifyRequest from body data
    public static func decode(from data: Data) throws -> HelloVerifyRequest {
        var reader = ByteReader([UInt8](data))
        let version: DTLSVersion
        let cookie: [UInt8]
        do {
            version = try DTLSVersion.decode(reader: &reader)
            cookie = try reader.readVector8()
        } catch let e as DTLSWireError {
            try e.rethrowUnwrapped()
        } catch {
            throw error
        }
        return HelloVerifyRequest(serverVersion: version, cookie: Data(cookie))
    }
}
