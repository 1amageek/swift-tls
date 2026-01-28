/// DTLS Version Constants (RFC 6347)
///
/// DTLS uses inverted version numbers: DTLS 1.2 = {254, 253} = 0xFEFD

import Foundation
@_exported import TLSCore

/// DTLS protocol version
public struct DTLSVersion: Sendable, Equatable, Hashable {
    public let major: UInt8
    public let minor: UInt8

    public init(major: UInt8, minor: UInt8) {
        self.major = major
        self.minor = minor
    }

    /// DTLS 1.0 (based on TLS 1.1)
    public static let v1_0 = DTLSVersion(major: 254, minor: 255) // 0xFEFF

    /// DTLS 1.2 (based on TLS 1.2)
    public static let v1_2 = DTLSVersion(major: 254, minor: 253) // 0xFEFD

    /// Wire format as UInt16
    public var rawValue: UInt16 {
        UInt16(major) << 8 | UInt16(minor)
    }

    /// Create from wire format UInt16
    public init(rawValue: UInt16) {
        self.major = UInt8(rawValue >> 8)
        self.minor = UInt8(rawValue & 0xFF)
    }

    /// Encode to wire format
    public func encode(writer: inout TLSWriter) {
        writer.writeUInt8(major)
        writer.writeUInt8(minor)
    }

    /// Decode from wire format
    public static func decode(reader: inout TLSReader) throws -> DTLSVersion {
        let major = try reader.readUInt8()
        let minor = try reader.readUInt8()
        return DTLSVersion(major: major, minor: minor)
    }
}

extension DTLSVersion: CustomStringConvertible {
    public var description: String {
        switch self {
        case .v1_0: return "DTLS 1.0"
        case .v1_2: return "DTLS 1.2"
        default: return "DTLS(\(major).\(minor))"
        }
    }
}
