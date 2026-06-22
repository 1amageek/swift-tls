/// TLS 1.3 Content Types (RFC 8446 Section 5.1)
///
/// Content types identify the type of payload in a TLS record.
///
/// Embedded-clean: pure value type, no Foundation. The Foundation-based `Data`
/// surface lives in the `TLSRecord` adapter.

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
