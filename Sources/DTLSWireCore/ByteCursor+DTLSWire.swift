/// Typed-throws wrappers over `P2PCoreBytes` reader/writer for the DTLS wire codec.
///
/// `ByteReader`/`ByteWriter` throw ``ByteError``; the DTLS wire codec throws
/// ``DTLSWireError``. Embedded Swift requires typed throws end-to-end (no
/// `any Error`), and typed-throws does not auto-convert between error types, so
/// these thin wrappers rewrap `ByteError` as `DTLSWireError.bytes` at each call.

import P2PCoreBytes

extension ByteReader {
    @inline(__always)
    mutating func dReadUInt8() throws(DTLSWireError) -> UInt8 {
        do { return try readUInt8() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadUInt16() throws(DTLSWireError) -> UInt16 {
        do { return try readUInt16() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadUInt24() throws(DTLSWireError) -> UInt32 {
        do { return try readUInt24() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadUInt32() throws(DTLSWireError) -> UInt32 {
        do { return try readUInt32() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadBytes(_ count: Int) throws(DTLSWireError) -> [UInt8] {
        do { return try readBytes(count) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadVector8() throws(DTLSWireError) -> [UInt8] {
        do { return try readVector8() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadVector16() throws(DTLSWireError) -> [UInt8] {
        do { return try readVector16() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dReadVector24() throws(DTLSWireError) -> [UInt8] {
        do { return try readVector24() } catch { throw .bytes(error) }
    }
}

extension ByteWriter {
    @inline(__always)
    mutating func dWriteUInt24(_ value: UInt32) throws(DTLSWireError) {
        do { try writeUInt24(value) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dWriteVector8(_ payload: [UInt8]) throws(DTLSWireError) {
        do { try writeVector8(payload) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dWriteVector16(_ payload: [UInt8]) throws(DTLSWireError) {
        do { try writeVector16(payload) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func dWriteVector24(_ payload: [UInt8]) throws(DTLSWireError) {
        do { try writeVector24(payload) } catch { throw .bytes(error) }
    }
}
