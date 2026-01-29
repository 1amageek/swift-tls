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

    /// Generate a cookie based on client address and random
    /// - Parameters:
    ///   - clientAddress: Client's network address (IP:port)
    ///   - secret: Server-side secret for HMAC
    /// - Returns: A HelloVerifyRequest with computed cookie
    public static func generate(
        clientAddress: Data,
        secret: SymmetricKey
    ) -> HelloVerifyRequest {
        let mac = HMAC<SHA256>.authenticationCode(for: clientAddress, using: secret)
        return HelloVerifyRequest(cookie: Data(mac))
    }

    /// Verify a cookie
    /// - Parameters:
    ///   - cookie: The cookie to verify
    ///   - clientAddress: Client's network address
    ///   - secret: Server-side secret
    /// - Returns: True if the cookie is valid
    public static func verifyCookie(
        _ cookie: Data,
        clientAddress: Data,
        secret: SymmetricKey
    ) -> Bool {
        let expected = HMAC<SHA256>.authenticationCode(for: clientAddress, using: secret)
        return constantTimeEqual(Data(expected), cookie)
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
