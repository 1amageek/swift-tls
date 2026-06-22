/// DTLS 1.2 Finished Message (RFC 5246 Section 7.4.9)
///
/// struct {
///   opaque verify_data[verify_data_length];  // 12 bytes for TLS 1.2
/// } Finished;
///
/// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))
///   where finished_label = "client finished" or "server finished"

import P2PCoreBytes

/// DTLS 1.2 Finished message
public struct DTLSFinished: Sendable {
    /// The verify_data (12 bytes)
    public let verifyData: [UInt8]

    /// Label for client Finished
    public static let clientLabel = "client finished"

    /// Label for server Finished
    public static let serverLabel = "server finished"

    public init(verifyData: [UInt8]) {
        self.verifyData = verifyData
    }

    /// Encode the Finished body
    public func encodeBytes() throws(DTLSWireError) -> [UInt8] {
        verifyData
    }

    /// Decode from body data
    public static func decode(from data: [UInt8]) throws(DTLSWireError) -> DTLSFinished {
        guard data.count == 12 else {
            throw DTLSWireError.dtls(.invalidFormat("Finished verify_data must be 12 bytes, got \(data.count)"))
        }
        return DTLSFinished(verifyData: data)
    }
}
