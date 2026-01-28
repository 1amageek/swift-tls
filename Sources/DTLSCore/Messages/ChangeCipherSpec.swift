/// DTLS 1.2 ChangeCipherSpec (RFC 5246 Section 7.1)
///
/// Not a handshake message — it's a record-layer message with its own content type.
/// struct {
///   enum { change_cipher_spec(1), (255) } type;
/// } ChangeCipherSpec;

import Foundation
import TLSCore

/// DTLS 1.2 ChangeCipherSpec message
public struct ChangeCipherSpec: Sendable {
    public init() {}

    /// Encode the CCS body (single byte: 0x01)
    public func encode() -> Data {
        Data([0x01])
    }

    /// Decode from body data
    public static func decode(from data: Data) throws -> ChangeCipherSpec {
        guard data.count == 1, data[0] == 0x01 else {
            throw DTLSError.invalidFormat("Invalid ChangeCipherSpec")
        }
        return ChangeCipherSpec()
    }
}
