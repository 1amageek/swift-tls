/// DTLS 1.2 Record Codec (RFC 6347 Section 4.1)
///
/// DTLS record header is 13 bytes:
///   ContentType:     1 byte
///   ProtocolVersion: 2 bytes
///   Epoch:           2 bytes  (DTLS-specific)
///   SequenceNumber:  6 bytes  (DTLS-specific)
///   Length:           2 bytes
///
/// TLS record header is 5 bytes (no epoch or sequence number).

import Foundation
import TLSCore
import DTLSCore
import DTLSWireCore
// Plain `import` (NOT `@_exported`): the Tier-3 DTLS record codec is not re-exported
// through this engine into the `TLS` facade's namespace (embedded-first-api.md §3.2).
import DTLSRecordCore

/// A decoded DTLS record
public struct DTLSRecord: Sendable, Equatable {
    /// Record content type
    public var contentType: DTLSContentType

    /// DTLS version
    public var version: DTLSVersion

    /// Epoch (increments on each CCS)
    public var epoch: UInt16

    /// 48-bit sequence number within the epoch
    public var sequenceNumber: UInt64

    /// Record payload
    public var fragment: Data

    /// DTLS record header size
    public static let headerSize = 13

    /// Maximum plaintext fragment size
    public static let maxPlaintextSize = 16384

    public init(
        contentType: DTLSContentType,
        version: DTLSVersion = .v1_2,
        epoch: UInt16 = 0,
        sequenceNumber: UInt64 = 0,
        fragment: Data
    ) {
        self.contentType = contentType
        self.version = version
        self.epoch = epoch
        self.sequenceNumber = sequenceNumber
        self.fragment = fragment
    }

    /// Encode the record to wire format
    public func encode() -> Data {
        var writer = TLSWriter()

        writer.writeUInt8(contentType.rawValue)
        version.encode(writer: &writer)
        writer.writeUInt16(epoch)

        // 6-byte sequence number (big-endian)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))

        writer.writeUInt16(UInt16(fragment.count))
        writer.writeBytes(fragment)

        return writer.finish()
    }

    /// Decode a single record from data
    /// - Parameter data: Input data (may contain multiple records)
    /// - Returns: Decoded record and number of bytes consumed, or nil if insufficient data
    public static func decode(from data: Data) throws -> (DTLSRecord, Int)? {
        guard data.count >= headerSize else {
            return nil
        }

        var reader = TLSReader(data: data)

        let contentTypeRaw = try reader.readUInt8()
        guard let contentType = DTLSContentType(rawValue: contentTypeRaw) else {
            throw DTLSRecordError.invalidContentType(contentTypeRaw)
        }

        let version = try DTLSVersion.decode(reader: &reader)
        let epoch = try reader.readUInt16()

        // 6-byte sequence number
        let seqHigh = try reader.readUInt16()
        let seqLow = try reader.readUInt32()
        let sequenceNumber = UInt64(seqHigh) << 32 | UInt64(seqLow)

        let length = try reader.readUInt16()

        guard data.count >= headerSize + Int(length) else {
            return nil // Need more data
        }

        let fragment = try reader.readBytes(Int(length))

        let record = DTLSRecord(
            contentType: contentType,
            version: version,
            epoch: epoch,
            sequenceNumber: sequenceNumber,
            fragment: fragment
        )

        return (record, headerSize + Int(length))
    }

    /// Build the additional authenticated data (AAD) for AEAD
    /// AAD = epoch (2) + sequence_number (6) + content_type (1) + version (2) + length (2)
    ///
    /// - Parameter plaintextLength: The plaintext fragment length. Must be a valid
    ///   16-bit value in `0...maxPlaintextSize`; otherwise this throws rather than
    ///   trapping on an out-of-range `UInt16` conversion.
    /// - Throws: `DTLSRecordError.invalidLength` if `plaintextLength` is negative or
    ///   exceeds the maximum 16-bit record length.
    public func buildAAD(plaintextLength: Int) throws -> Data {
        guard plaintextLength >= 0,
              let length16 = UInt16(exactly: plaintextLength) else {
            throw DTLSRecordError.invalidLength(plaintextLength)
        }
        var writer = TLSWriter()
        writer.writeUInt16(epoch)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))
        writer.writeUInt8(contentType.rawValue)
        version.encode(writer: &writer)
        writer.writeUInt16(length16)
        return writer.finish()
    }
}

// MARK: - Record Decode Result

/// Result of decoding a DTLS record
///
/// RFC 6347 §4.1.2.6 requires that replayed or too-old records be silently discarded,
/// but the datagram processing should continue to subsequent records.
public enum RecordDecodeResult: Sendable {
    /// A valid record was decoded
    case record(DTLSRecord, consumed: Int)

    /// Insufficient data to decode a complete record
    case insufficientData

    /// Record was discarded (processing should continue to next record)
    case discarded(consumed: Int, reason: DiscardReason)
}
