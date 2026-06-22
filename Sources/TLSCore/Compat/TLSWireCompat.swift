/// Foundation `Data` compatibility layer over the Embedded-clean `TLSWireCore`.
///
/// `TLSWireCore` expresses the TLS wire codec over `[UInt8]`/`P2PCoreBytes` so it
/// can build under Embedded Swift. This adapter file restores the historical
/// `Data`-based public surface that the rest of `swift-tls` (state machines,
/// X.509 glue, DTLS) and the existing test suite bind to. It is pure bridging:
/// `Data <-> [UInt8]` conversions plus the legacy `Data`-based `TLSReader` /
/// `TLSWriter` carried over verbatim. No new protocol or wire logic lives here.

import Foundation
import P2PCoreBytes
@_exported import TLSWireCore

// MARK: - Constant-time comparison (Data)

/// Compare two `Data` values in constant time.
///
/// Mirrors ``TLSWireCore/constantTimeEqual(_:_:)`` for callers still working
/// with Foundation `Data`.
public func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    constantTimeEqual([UInt8](a), [UInt8](b))
}

// MARK: - Byte-array <-> Data equality bridges

// The wire types store byte fields as `[UInt8]`. These overloads let existing
// call sites (and tests) compare those fields directly to `Data` values without
// an explicit conversion.

public func == (lhs: [UInt8], rhs: Data) -> Bool { lhs == [UInt8](rhs) }
public func == (lhs: Data, rhs: [UInt8]) -> Bool { [UInt8](lhs) == rhs }
public func != (lhs: [UInt8], rhs: Data) -> Bool { !(lhs == rhs) }
public func != (lhs: Data, rhs: [UInt8]) -> Bool { !(lhs == rhs) }

// Optional forms, for `someMessage.optionalByteField == someData`.
public func == (lhs: [UInt8]?, rhs: Data) -> Bool { lhs.map { $0 == rhs } ?? false }
public func == (lhs: Data, rhs: [UInt8]?) -> Bool { rhs.map { lhs == $0 } ?? false }
public func != (lhs: [UInt8]?, rhs: Data) -> Bool { !(lhs == rhs) }
public func != (lhs: Data, rhs: [UInt8]?) -> Bool { !(lhs == rhs) }

// Mixed forms where the right-hand side is the optional (e.g. comparing a
// non-optional wire field against an optional stored `Data?`).
public func == (lhs: [UInt8], rhs: Data?) -> Bool { rhs.map { lhs == $0 } ?? false }
public func == (lhs: Data?, rhs: [UInt8]) -> Bool { lhs.map { $0 == rhs } ?? false }
public func != (lhs: [UInt8], rhs: Data?) -> Bool { !(lhs == rhs) }
public func != (lhs: Data?, rhs: [UInt8]) -> Bool { !(lhs == rhs) }

// MARK: - TLSWireError unwrapping

extension TLSWireError {
    /// Rethrows the *wrapped* concrete error (`ByteError` / `TLSDecodeError` /
    /// `TLSHandshakeError`).
    ///
    /// The Embedded-clean core uses a single typed-throws error (`TLSWireError`);
    /// this restores the historical behaviour where callers (and the test suite)
    /// catch `TLSDecodeError` / `TLSHandshakeError` / `ByteError` directly.
    ///
    /// Usage at a `Data`-API boundary that calls a typed-throws core method:
    /// ```swift
    /// do { return try coreCall() } catch { try error.rethrowUnwrapped() }
    /// ```
    /// In the bare `catch`, `error` has static type `TLSWireError` (the core's
    /// typed throw), so this avoids the generic-helper / `catch as` forms that
    /// currently miscompile with typed throws.
    public func rethrowUnwrapped() throws -> Never {
        switch self {
        case .bytes(let e): throw e
        case .decode(let e): throw e
        case .handshake(let e): throw e
        }
    }
}

// MARK: - HandshakeCodec (Data)

extension HandshakeCodec {
    /// Encodes a handshake message with header, `Data` in / `Data` out.
    public static func encode(type: HandshakeType, content: Data) -> Data {
        Data(encodeBytes(type: type, content: [UInt8](content)))
    }

    /// Decodes a handshake message header from `Data`.
    public static func decodeHeader(from data: Data) throws -> (HandshakeType, Int) {
        do { return try decodeHeader(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// Decodes a complete handshake message from `Data`.
    public static func decodeMessage(from data: Data) throws -> (HandshakeType, Data, Int) {
        let result: (HandshakeType, [UInt8], Int)
        do {
            result = try decodeMessage(from: [UInt8](data))
        } catch {
            try error.rethrowUnwrapped()
        }
        return (result.0, Data(result.1), result.2)
    }
}

// MARK: - TLS Reader (Data-backed, legacy API)

/// Helper for reading TLS data structures over Foundation `Data`.
///
/// Retained as the adapter's `Data`-based cursor for code (DTLS message codecs,
/// tests, X.509 glue) that has not migrated to ``P2PCoreBytes/ByteReader``. The
/// Embedded-clean codec inside ``TLSWireCore`` uses `ByteReader` instead.
public struct TLSReader {
    private var data: Data
    private var offset: Int

    public init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    /// Remaining bytes to read
    public var remaining: Int {
        data.endIndex - offset
    }

    /// Whether there are more bytes to read
    public var hasMore: Bool {
        remaining > 0
    }

    /// Read a single byte
    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else {
            throw TLSDecodeError.insufficientData(expected: 1, actual: remaining)
        }
        let value = data[offset]
        offset += 1
        return value
    }

    /// Read a 16-bit big-endian integer
    public mutating func readUInt16() throws -> UInt16 {
        guard remaining >= 2 else {
            throw TLSDecodeError.insufficientData(expected: 2, actual: remaining)
        }
        let value = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2
        return value
    }

    /// Read a 24-bit big-endian integer
    public mutating func readUInt24() throws -> UInt32 {
        guard remaining >= 3 else {
            throw TLSDecodeError.insufficientData(expected: 3, actual: remaining)
        }
        let value = UInt32(data[offset]) << 16 |
                    UInt32(data[offset + 1]) << 8 |
                    UInt32(data[offset + 2])
        offset += 3
        return value
    }

    /// Read a 32-bit big-endian integer
    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else {
            throw TLSDecodeError.insufficientData(expected: 4, actual: remaining)
        }
        let value = UInt32(data[offset]) << 24 |
                    UInt32(data[offset + 1]) << 16 |
                    UInt32(data[offset + 2]) << 8 |
                    UInt32(data[offset + 3])
        offset += 4
        return value
    }

    /// Read exact number of bytes
    public mutating func readBytes(_ count: Int) throws -> Data {
        guard remaining >= count else {
            throw TLSDecodeError.insufficientData(expected: count, actual: remaining)
        }
        let bytes = data.subdata(in: offset..<(offset + count))
        offset += count
        return bytes
    }

    /// Read a variable-length vector with 1-byte length prefix
    public mutating func readVector8() throws -> Data {
        let length = Int(try readUInt8())
        return try readBytes(length)
    }

    /// Read a variable-length vector with 2-byte length prefix
    public mutating func readVector16() throws -> Data {
        let length = Int(try readUInt16())
        return try readBytes(length)
    }

    /// Read a variable-length vector with 3-byte length prefix
    public mutating func readVector24() throws -> Data {
        let length = Int(try readUInt24())
        return try readBytes(length)
    }

    /// Read all remaining bytes
    public mutating func readRemaining() -> Data {
        let bytes = data.subdata(in: offset..<data.endIndex)
        offset = data.endIndex
        return bytes
    }

    /// Create a sub-reader for a portion of data
    public mutating func subReader(length: Int) throws -> TLSReader {
        let subData = try readBytes(length)
        return TLSReader(data: subData)
    }
}

// MARK: - TLS Writer (Data-backed, legacy API)

/// Helper for writing TLS data structures over Foundation `Data`.
public struct TLSWriter {
    private var data: Data

    public init(capacity: Int = 256) {
        self.data = Data(capacity: capacity)
    }

    /// Get the written data
    public func finish() -> Data {
        data
    }

    /// Current size
    public var count: Int {
        data.count
    }

    /// Write a single byte
    public mutating func writeUInt8(_ value: UInt8) {
        data.append(value)
    }

    /// Write a 16-bit big-endian integer
    public mutating func writeUInt16(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Write a 24-bit big-endian integer
    public mutating func writeUInt24(_ value: UInt32) {
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Write a 32-bit big-endian integer
    public mutating func writeUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Write raw bytes
    public mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }

    /// Write a variable-length vector with 1-byte length prefix
    public mutating func writeVector8(_ bytes: Data) {
        writeUInt8(UInt8(bytes.count))
        writeBytes(bytes)
    }

    /// Write a variable-length vector with 2-byte length prefix
    public mutating func writeVector16(_ bytes: Data) {
        writeUInt16(UInt16(bytes.count))
        writeBytes(bytes)
    }

    /// Write a variable-length vector with 3-byte length prefix
    public mutating func writeVector24(_ bytes: Data) {
        writeUInt24(UInt32(bytes.count))
        writeBytes(bytes)
    }
}
