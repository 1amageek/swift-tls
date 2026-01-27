/// TLS 1.3 Record Layer Framing (RFC 8446 Section 5)
///
/// Handles encoding and decoding of TLS record layer frames.
/// A TLS record consists of:
/// - ContentType (1 byte)
/// - ProtocolVersion (2 bytes, always 0x0303 for TLS 1.3)
/// - Length (2 bytes)
/// - Fragment (variable)

import Foundation

// MARK: - TLS Record

/// A decoded TLS record
public struct TLSRecord: Sendable {
    /// The content type of this record
    public let contentType: TLSContentType

    /// The record fragment (plaintext or ciphertext)
    public let fragment: Data

    public init(contentType: TLSContentType, fragment: Data) {
        self.contentType = contentType
        self.fragment = fragment
    }
}

// MARK: - TLS Record Codec

/// Codec for TLS record layer framing (RFC 8446 Section 5)
public enum TLSRecordCodec {

    /// Maximum plaintext fragment size (RFC 8446 Section 5.1)
    public static let maxPlaintextSize = 16384

    /// Maximum ciphertext fragment size (RFC 8446 Section 5.2)
    /// Plaintext + content type (1) + AEAD tag (max 255, typically 16)
    public static let maxCiphertextSize = 16384 + 256

    /// TLS record header size: ContentType(1) + Version(2) + Length(2)
    public static let headerSize = 5

    /// Legacy protocol version (0x0303 = TLS 1.2, used in TLS 1.3 records)
    public static let legacyVersion: UInt16 = 0x0303

    // MARK: - Encoding

    /// Encode a plaintext record
    /// - Parameters:
    ///   - type: The content type
    ///   - data: The plaintext fragment
    /// - Returns: The encoded TLS record
    public static func encodePlaintext(type: TLSContentType, data: Data) -> Data {
        var record = Data(capacity: headerSize + data.count)
        record.append(type.rawValue)
        record.append(UInt8(legacyVersion >> 8))
        record.append(UInt8(legacyVersion & 0xFF))
        record.append(UInt8(data.count >> 8))
        record.append(UInt8(data.count & 0xFF))
        record.append(data)
        return record
    }

    /// Encode a ciphertext record (always uses applicationData content type and 0x0303 version)
    /// - Parameter ciphertext: The encrypted record body (inner plaintext + AEAD tag)
    /// - Returns: The encoded TLS ciphertext record
    public static func encodeCiphertext(_ ciphertext: Data) -> Data {
        var record = Data(capacity: headerSize + ciphertext.count)
        record.append(TLSContentType.applicationData.rawValue)
        record.append(UInt8(legacyVersion >> 8))
        record.append(UInt8(legacyVersion & 0xFF))
        record.append(UInt8(ciphertext.count >> 8))
        record.append(UInt8(ciphertext.count & 0xFF))
        record.append(ciphertext)
        return record
    }

    // MARK: - Decoding

    /// Decode a single TLS record from a buffer.
    ///
    /// - Parameter buffer: The input buffer (may contain partial or multiple records)
    /// - Returns: A tuple of (decoded record, bytes consumed), or nil if the buffer
    ///   doesn't contain a complete record yet
    /// - Throws: ``TLSRecordError`` if the record is malformed
    public static func decode(from buffer: Data) throws -> (TLSRecord, Int)? {
        guard buffer.count >= headerSize else {
            return nil // Need more data
        }

        let startIndex = buffer.startIndex
        guard let contentType = TLSContentType(rawValue: buffer[startIndex]) else {
            throw TLSRecordError.invalidContentType(buffer[startIndex])
        }

        // Version check (accept 0x0301 or 0x0303)
        let versionHigh = buffer[startIndex + 1]
        let versionLow = buffer[startIndex + 2]
        let version = UInt16(versionHigh) << 8 | UInt16(versionLow)
        guard version == 0x0303 || version == 0x0301 else {
            throw TLSRecordError.unsupportedVersion(version)
        }

        let lengthHigh = Int(buffer[startIndex + 3])
        let lengthLow = Int(buffer[startIndex + 4])
        let fragmentLength = (lengthHigh << 8) | lengthLow

        // Validate length
        guard fragmentLength <= maxCiphertextSize else {
            throw TLSRecordError.recordOverflow(fragmentLength)
        }

        let totalLength = headerSize + fragmentLength
        guard buffer.count >= totalLength else {
            return nil // Need more data
        }

        let fragment = buffer[buffer.index(startIndex, offsetBy: headerSize)..<buffer.index(startIndex, offsetBy: totalLength)]

        let record = TLSRecord(
            contentType: contentType,
            fragment: Data(fragment)
        )
        return (record, totalLength)
    }
}

// MARK: - Record Errors

/// Errors from TLS record layer operations
public enum TLSRecordError: Error, Sendable {
    /// Invalid content type byte
    case invalidContentType(UInt8)
    /// Unsupported protocol version
    case unsupportedVersion(UInt16)
    /// Record fragment exceeds maximum size
    case recordOverflow(Int)
    /// Decryption failed (bad record MAC)
    case badRecordMac
    /// Record too large for encryption
    case plaintextTooLarge(Int)
    /// No keys configured for encryption/decryption
    case noKeysAvailable
    /// Invalid inner plaintext (missing content type after decryption)
    case invalidInnerPlaintext
}
