/// DTLS 1.2 ClientKeyExchange (RFC 5246 Section 7.4.7)
///
/// For ECDHE:
/// struct {
///   opaque ecdh_Yc<1..2^8-1>;  // Client's ECDH public key
/// } ClientKeyExchange;

import Foundation
import TLSCore

/// DTLS 1.2 ClientKeyExchange message for ECDHE
public struct ClientKeyExchange: Sendable {
    /// Client's ephemeral ECDH public key
    public let publicKey: Data

    public init(publicKey: Data) {
        self.publicKey = publicKey
    }

    /// Encode the ClientKeyExchange body
    public func encode() -> Data {
        var writer = TLSWriter()
        writer.writeVector8(publicKey)
        return writer.finish()
    }

    /// Decode from body data
    public static func decode(from data: Data) throws -> ClientKeyExchange {
        var reader = TLSReader(data: data)
        let publicKey = try reader.readVector8()
        return ClientKeyExchange(publicKey: publicKey)
    }
}
