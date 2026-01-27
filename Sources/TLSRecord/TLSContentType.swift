/// TLS 1.3 Content Types (RFC 8446 Section 5.1)
///
/// Content types identify the type of payload in a TLS record.

import Foundation

/// TLS 1.3 content types
public enum TLSContentType: UInt8, Sendable {
    /// Change cipher spec (legacy, used for middlebox compatibility)
    case changeCipherSpec = 20
    /// Alert message
    case alert = 21
    /// Handshake message
    case handshake = 22
    /// Application data
    case applicationData = 23
}
