/// A TLS signature-scheme identifier without exposing the mechanism module's
/// concrete signing implementation.
public struct TLSSignatureScheme: RawRepresentable, Sendable, Hashable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let ecdsaP256SHA256 = Self(rawValue: 0x0403)
    public static let ecdsaP384SHA384 = Self(rawValue: 0x0503)
    public static let ed25519 = Self(rawValue: 0x0807)
    public static let rsaPSSRSAESHA256 = Self(rawValue: 0x0804)
    public static let rsaPSSRSAESHA384 = Self(rawValue: 0x0805)
    public static let rsaPSSRSAESHA512 = Self(rawValue: 0x0806)
}
