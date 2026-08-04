import DTLSWireCore

/// An SRTP protection profile negotiated through the public DTLS facade.
///
/// The facade owns this type so callers never need to import the internal
/// `DTLSWireCore` module merely to configure WebRTC media protection.
public struct DTLSSRTPProtectionProfile: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// SRTP_AES128_CM_HMAC_SHA1_80 (RFC 5764 section 4.1.2).
    public static let aes128CMHMACSHA180 = DTLSSRTPProtectionProfile(rawValue: 0x0001)

    init(wireProfile: SRTPProtectionProfile) {
        self.init(rawValue: wireProfile.rawValue)
    }

    var wireProfile: SRTPProtectionProfile {
        SRTPProtectionProfile(rawValue: rawValue)
    }
}
