/// TLS 1.3 Handshake Message Types (RFC 8446 Section 4)
///
/// All TLS handshake messages share a common header format:
/// ```
/// struct {
///     HandshakeType msg_type;    /* 1 byte */
///     uint24 length;             /* 3 bytes */
///     [message content]
/// } Handshake;
/// ```
///
/// Embedded-clean: the wire codec is expressed over `P2PCoreBytes`
/// (`ByteReader`/`ByteWriter`), not Foundation `Data`. The Foundation-based
/// `TLSReader`/`TLSWriter` and `Data` entry points live in the `TLSCore`
/// adapter.

import P2PCoreBytes

// MARK: - Handshake Type

/// TLS 1.3 handshake message types (RFC 8446 Section 4)
public enum HandshakeType: UInt8, Sendable {
    case clientHello = 1
    case serverHello = 2
    case newSessionTicket = 4
    case endOfEarlyData = 5
    case encryptedExtensions = 8
    case certificate = 11
    case certificateRequest = 13
    case certificateVerify = 15
    case finished = 20
    case keyUpdate = 24
    case messageHash = 254
}

// MARK: - TLS Constants

/// TLS protocol constants
public enum TLSConstants {
    /// TLS 1.3 version (0x0304)
    public static let version13: UInt16 = 0x0304

    /// TLS 1.2 version for legacy compatibility (0x0303)
    public static let legacyVersion: UInt16 = 0x0303

    /// Random bytes length
    public static let randomLength = 32

    /// Session ID max length
    public static let sessionIDMaxLength = 32

    /// Verify data length for Finished message (SHA-256)
    public static let verifyDataLength = 32

    /// HelloRetryRequest magic random value (SHA-256 of "HelloRetryRequest")
    public static let helloRetryRequestRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ]
}

// MARK: - Cipher Suite

/// TLS 1.3 cipher suites (RFC 8446 Section B.4)
public enum CipherSuite: UInt16, Sendable, CaseIterable {
    case tls_aes_128_gcm_sha256 = 0x1301
    case tls_aes_256_gcm_sha384 = 0x1302
    case tls_chacha20_poly1305_sha256 = 0x1303

    /// Key length in bytes
    public var keyLength: Int {
        switch self {
        case .tls_aes_128_gcm_sha256: return 16
        case .tls_aes_256_gcm_sha384: return 32
        case .tls_chacha20_poly1305_sha256: return 32
        }
    }

    /// IV length in bytes (all TLS 1.3 cipher suites use 12 bytes)
    public var ivLength: Int { 12 }

    /// Hash output length in bytes
    public var hashLength: Int {
        switch self {
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256: return 32
        case .tls_aes_256_gcm_sha384: return 48
        }
    }
}

// MARK: - Named Group

/// Named groups for key exchange (RFC 8446 Section 4.2.7)
public enum NamedGroup: UInt16, Sendable {
    case secp256r1 = 0x0017
    case secp384r1 = 0x0018
    case secp521r1 = 0x0019
    case x25519 = 0x001D
    case x448 = 0x001E

    /// Post-quantum hybrid: X25519 + ML-KEM-768 (draft-ietf-tls-ecdhe-mlkem)
    case x25519MLKEM768 = 0x11EC
}

// MARK: - Signature Scheme

/// Signature schemes (RFC 8446 Section 4.2.3)
public enum SignatureScheme: UInt16, Sendable {
    // ECDSA
    case ecdsa_secp256r1_sha256 = 0x0403
    case ecdsa_secp384r1_sha384 = 0x0503
    case ecdsa_secp521r1_sha512 = 0x0603

    // RSASSA-PSS with rsaEncryption OID
    case rsa_pss_rsae_sha256 = 0x0804
    case rsa_pss_rsae_sha384 = 0x0805
    case rsa_pss_rsae_sha512 = 0x0806

    // EdDSA
    case ed25519 = 0x0807
    case ed448 = 0x0808

    // RSASSA-PKCS1-v1_5 (for certificates only)
    case rsa_pkcs1_sha256 = 0x0401
    case rsa_pkcs1_sha384 = 0x0501
    case rsa_pkcs1_sha512 = 0x0601
}

// MARK: - Handshake Codec

/// Encoder/decoder for TLS handshake messages
public enum HandshakeCodec {

    /// Encodes a handshake message with header
    /// - Parameters:
    ///   - type: The message type
    ///   - content: The message content (without header)
    /// - Returns: Complete message with 4-byte header
    public static func encodeBytes(type: HandshakeType, content: [UInt8]) -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(4 + content.count)

        // HandshakeType (1 byte)
        data.append(type.rawValue)

        // Length (3 bytes, big-endian)
        let length = UInt32(content.count)
        data.append(UInt8((length >> 16) & 0xFF))
        data.append(UInt8((length >> 8) & 0xFF))
        data.append(UInt8(length & 0xFF))

        // Content
        data.append(contentsOf: content)

        return data
    }

    /// Decodes a handshake message header
    /// - Parameter data: Bytes containing at least 4 bytes
    /// - Returns: Tuple of (messageType, contentLength)
    public static func decodeHeader(from data: [UInt8]) throws(TLSWireError) -> (HandshakeType, Int) {
        guard data.count >= 4 else {
            throw TLSWireError.decode(.insufficientData(expected: 4, actual: data.count))
        }

        guard let messageType = HandshakeType(rawValue: data[0]) else {
            throw TLSWireError.decode(.unknownHandshakeType(data[0]))
        }

        let length = Int(data[1]) << 16 |
                     Int(data[2]) << 8 |
                     Int(data[3])

        return (messageType, length)
    }

    /// Decodes a complete handshake message
    /// - Parameter data: Bytes containing header and content
    /// - Returns: Tuple of (messageType, content, totalBytesConsumed)
    public static func decodeMessage(from data: [UInt8]) throws(TLSWireError) -> (HandshakeType, [UInt8], Int) {
        let (messageType, contentLength) = try decodeHeader(from: data)

        let totalLength = 4 + contentLength
        guard data.count >= totalLength else {
            throw TLSWireError.decode(.insufficientData(expected: totalLength, actual: data.count))
        }

        let content = Array(data[4..<totalLength])
        return (messageType, content, totalLength)
    }
}

// MARK: - Errors

/// Errors during TLS decoding
public enum TLSDecodeError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case unknownHandshakeType(UInt8)
    case unknownExtensionType(UInt16)
    case invalidFormat(String)
    case unsupportedVersion(UInt16)
    case unexpectedMessage(expected: HandshakeType, received: HandshakeType)
}
