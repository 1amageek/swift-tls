/// DTLS 1.2 Cipher Suites
///
/// TLS 1.2 cipher suites used in DTLS. WebRTC mandates ECDHE_ECDSA suites.
/// These differ from TLS 1.3 cipher suites (0x1301 etc.) in code values and semantics.

import Foundation
import TLSCore

/// DTLS 1.2 cipher suite identifiers
public enum DTLSCipherSuite: UInt16, Sendable, CaseIterable {
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (WebRTC mandatory)
    case ecdheEcdsaWithAes128GcmSha256 = 0xC02B

    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    case ecdheEcdsaWithAes256GcmSha384 = 0xC02C

    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    case ecdheRsaWithAes128GcmSha256 = 0xC02F

    /// Symmetric key length in bytes
    public var keyLength: Int {
        switch self {
        case .ecdheEcdsaWithAes128GcmSha256, .ecdheRsaWithAes128GcmSha256:
            return 16
        case .ecdheEcdsaWithAes256GcmSha384:
            return 32
        }
    }

    /// Fixed IV length in bytes (DTLS 1.2 uses 4-byte fixed + 8-byte explicit nonce)
    public var fixedIVLength: Int {
        4
    }

    /// Explicit nonce length in bytes
    public var explicitNonceLength: Int {
        8
    }

    /// Total nonce length (fixed + explicit = 12 bytes for AES-GCM)
    public var nonceLength: Int {
        fixedIVLength + explicitNonceLength
    }

    /// AEAD tag length in bytes
    public var tagLength: Int {
        16
    }

    /// Hash algorithm used for PRF
    public var hashAlgorithm: HashAlgorithm {
        switch self {
        case .ecdheEcdsaWithAes128GcmSha256, .ecdheRsaWithAes128GcmSha256:
            return .sha256
        case .ecdheEcdsaWithAes256GcmSha384:
            return .sha384
        }
    }

    /// Hash output length in bytes
    public var hashLength: Int {
        switch hashAlgorithm {
        case .sha256: return 32
        case .sha384: return 48
        }
    }

    /// Whether this suite uses ECDSA (vs RSA) for authentication
    public var usesECDSA: Bool {
        switch self {
        case .ecdheEcdsaWithAes128GcmSha256, .ecdheEcdsaWithAes256GcmSha384:
            return true
        case .ecdheRsaWithAes128GcmSha256:
            return false
        }
    }

    /// Encode to wire format
    public func encode(writer: inout TLSWriter) {
        writer.writeUInt16(rawValue)
    }

    /// Decode from wire format
    public static func decode(reader: inout TLSReader) throws -> DTLSCipherSuite {
        let value = try reader.readUInt16()
        guard let suite = DTLSCipherSuite(rawValue: value) else {
            throw DTLSError.unsupportedCipherSuite(value)
        }
        return suite
    }
}

/// Hash algorithm identifier for PRF
public enum HashAlgorithm: UInt8, Sendable {
    case sha256 = 4
    case sha384 = 5
}

extension DTLSCipherSuite: CustomStringConvertible {
    public var description: String {
        switch self {
        case .ecdheEcdsaWithAes128GcmSha256:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        case .ecdheEcdsaWithAes256GcmSha384:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        case .ecdheRsaWithAes128GcmSha256:
            return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
    }
}
