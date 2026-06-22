/// DTLS 1.2 ClientKeyExchange (RFC 5246 Section 7.4.7)
///
/// For ECDHE:
/// struct {
///   opaque ecdh_Yc<1..2^8-1>;  // Client's ECDH public key
/// } ClientKeyExchange;

import P2PCoreBytes

/// DTLS 1.2 ClientKeyExchange message for ECDHE
public struct ClientKeyExchange: Sendable {
    /// Client's ephemeral ECDH public key
    public let publicKey: [UInt8]

    public init(publicKey: [UInt8]) {
        self.publicKey = publicKey
    }

    /// Encode the ClientKeyExchange body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        var writer = ByteWriter()
        try writer.dWriteVector8(publicKey)
        return writer.finishArray()
    }

    /// Decode from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> ClientKeyExchange {
        var reader = ByteReader(data)
        let publicKey = try reader.dReadVector8()
        return ClientKeyExchange(publicKey: publicKey)
    }
}
