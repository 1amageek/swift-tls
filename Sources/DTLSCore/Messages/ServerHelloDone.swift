/// DTLS 1.2 ServerHelloDone (RFC 5246 Section 7.4.5)
///
/// Empty message signaling end of server's hello sequence.
/// struct {} ServerHelloDone;

import Foundation
import TLSCore

/// DTLS 1.2 ServerHelloDone message (empty body)
public struct ServerHelloDone: Sendable {
    public init() {}

    /// Encode (empty body)
    public func encode() -> Data {
        Data()
    }

    /// Decode (no body to parse)
    public static func decode(from data: Data) throws -> ServerHelloDone {
        ServerHelloDone()
    }
}
