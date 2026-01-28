/// DTLS 1.2 Content Types (RFC 6347 / RFC 5246)
///
/// Content types identify the type of payload in a DTLS record.
/// Same values as TLS, but defined separately to avoid depending on TLSRecord.

import Foundation

/// DTLS record content types
public enum DTLSContentType: UInt8, Sendable, Equatable {
    /// Change cipher spec
    case changeCipherSpec = 20
    /// Alert message
    case alert = 21
    /// Handshake message
    case handshake = 22
    /// Application data
    case applicationData = 23
}
