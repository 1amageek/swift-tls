/// DTLS 1.2 ServerHelloDone (RFC 5246 Section 7.4.5)
///
/// Empty message signaling end of server's hello sequence.
/// struct {} ServerHelloDone;

import P2PCoreBytes

/// DTLS 1.2 ServerHelloDone message (empty body)
public struct ServerHelloDone: Sendable {
    public init() {}

    /// Encode (empty body)
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        []
    }

    /// Decode (no body to parse)
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> ServerHelloDone {
        ServerHelloDone()
    }
}
