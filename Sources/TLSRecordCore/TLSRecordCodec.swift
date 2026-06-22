/// TLS 1.3 Record Layer Framing (RFC 8446 Section 5)
///
/// Handles encoding and decoding of TLS record layer frames.
/// A TLS record consists of:
/// - ContentType (1 byte)
/// - ProtocolVersion (2 bytes, always 0x0303 for TLS 1.3)
/// - Length (2 bytes)
/// - Fragment (variable)
///
/// Embedded-clean: the codec is expressed over `[UInt8]`, not Foundation `Data`.
/// The decode path uses manual `[UInt8]` indexing (no `ByteReader`) to preserve
/// the original control flow exactly, including the `nil`-returning
/// "need more data" cases. The Foundation-based `Data` entry points live in the
/// `TLSRecord` adapter. Decode uses typed throws (``TLSRecordError``).

// MARK: - TLS Record

/// A decoded TLS record
public struct TLSRecord: Sendable {
    /// The content type of this record
    public let contentType: TLSContentType

    /// The record fragment (plaintext or ciphertext)
    public let fragment: [UInt8]

    public init(contentType: TLSContentType, fragment: [UInt8]) {
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
    public static func encodePlaintext(type: TLSContentType, data: [UInt8]) -> [UInt8] {
        var record = [UInt8]()
        record.reserveCapacity(headerSize + data.count)
        record.append(type.rawValue)
        record.append(UInt8((legacyVersion >> 8) & 0xFF))
        record.append(UInt8(legacyVersion & 0xFF))
        record.append(UInt8((data.count >> 8) & 0xFF))
        record.append(UInt8(data.count & 0xFF))
        record.append(contentsOf: data)
        return record
    }

    /// Encode a ciphertext record (always uses applicationData content type and 0x0303 version)
    /// - Parameter ciphertext: The encrypted record body (inner plaintext + AEAD tag)
    /// - Returns: The encoded TLS ciphertext record
    public static func encodeCiphertext(_ ciphertext: [UInt8]) -> [UInt8] {
        var record = [UInt8]()
        record.reserveCapacity(headerSize + ciphertext.count)
        record.append(TLSContentType.applicationData.rawValue)
        record.append(UInt8((legacyVersion >> 8) & 0xFF))
        record.append(UInt8(legacyVersion & 0xFF))
        record.append(UInt8((ciphertext.count >> 8) & 0xFF))
        record.append(UInt8(ciphertext.count & 0xFF))
        record.append(contentsOf: ciphertext)
        return record
    }

    // MARK: - Decoding

    /// Decode a single TLS record from a buffer.
    ///
    /// - Parameter buffer: The input buffer (may contain partial or multiple records)
    /// - Returns: A tuple of (decoded record, bytes consumed), or nil if the buffer
    ///   doesn't contain a complete record yet
    /// - Throws: ``TLSRecordError`` if the record is malformed
    public static func decode(from buffer: [UInt8]) throws(TLSRecordError) -> (TLSRecord, Int)? {
        guard buffer.count >= headerSize else {
            return nil // Need more data
        }

        guard let contentType = TLSContentType(rawValue: buffer[0]) else {
            throw TLSRecordError.invalidContentType(buffer[0])
        }

        // Version check (accept 0x0301 or 0x0303)
        let versionHigh = buffer[1]
        let versionLow = buffer[2]
        let version = UInt16(versionHigh) << 8 | UInt16(versionLow)
        guard version == 0x0303 || version == 0x0301 else {
            throw TLSRecordError.unsupportedVersion(version)
        }

        let lengthHigh = Int(buffer[3])
        let lengthLow = Int(buffer[4])
        let fragmentLength = (lengthHigh << 8) | lengthLow

        // Validate length
        guard fragmentLength <= maxCiphertextSize else {
            throw TLSRecordError.recordOverflow(fragmentLength)
        }

        let totalLength = headerSize + fragmentLength
        guard buffer.count >= totalLength else {
            return nil // Need more data
        }

        let fragment = Array(buffer[headerSize..<totalLength])

        let record = TLSRecord(
            contentType: contentType,
            fragment: fragment
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
    /// Sequence number would overflow; key update required (RFC 8446 Section 5.3)
    case sequenceNumberOverflow
    /// Application data received before encryption is active
    case unexpectedPlaintextApplicationData
    /// Plaintext handshake record received after encryption is active (RFC 8446 Section 5)
    case unexpectedPlaintextHandshake
    /// Plaintext alert record received after encryption is active (RFC 8446 Section 5)
    case unexpectedPlaintextAlert
    /// Receive buffer exceeded maximum size
    case bufferOverflow
    /// Invalid key parameters (wrong size IV, etc.)
    case invalidKey(String)
}
