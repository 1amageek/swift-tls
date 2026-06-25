/// Engine-local typed-throws wrappers over `P2PCoreBytes` reader/writer.
///
/// The `dRead*` / `dWrite*` helpers in ``DTLSWireCore`` are `internal` to that
/// target, so the engine cannot reuse them. These mirror them inside
/// `DTLSEngineCore`: each rewraps the base ``P2PCoreBytes/ByteError`` as a
/// ``DTLSEngineError`` (the engine's single typed-throws surface), so no error is
/// ever swallowed and typed-throws stays closed end-to-end (Embedded requirement).

import P2PCoreBytes
import DTLSWireCore

/// Decodes a complete handshake message (`rawMessage` = 12-byte header + body) into
/// its (header, body) pair, mapping wire errors to ``DTLSEngineError``. Shared by
/// the client and server engines' dispatch.
func decodeHandshakeMessage(
    _ rawMessage: [UInt8]
) throws(DTLSEngineError) -> (header: DTLSHandshakeHeader, body: [UInt8]) {
    var reader = ByteReader(rawMessage)
    let header: DTLSHandshakeHeader
    do { header = try DTLSHandshakeHeader.decode(reader: &reader) }
    catch { throw .from(wire: error) }
    let body = try reader.eReadBytes(Int(header.fragmentLength))
    return (header, body)
}

extension ByteReader {
    @inline(__always)
    mutating func eReadUInt8() throws(DTLSEngineError) -> UInt8 {
        do { return try readUInt8() } catch { throw .protocolFailure(reason: "byte read failed: \(error)") }
    }

    @inline(__always)
    mutating func eReadUInt16() throws(DTLSEngineError) -> UInt16 {
        do { return try readUInt16() } catch { throw .protocolFailure(reason: "byte read failed: \(error)") }
    }

    @inline(__always)
    mutating func eReadUInt32() throws(DTLSEngineError) -> UInt32 {
        do { return try readUInt32() } catch { throw .protocolFailure(reason: "byte read failed: \(error)") }
    }

    @inline(__always)
    mutating func eReadBytes(_ count: Int) throws(DTLSEngineError) -> [UInt8] {
        do { return try readBytes(count) } catch { throw .protocolFailure(reason: "byte read failed: \(error)") }
    }

    @inline(__always)
    mutating func eSkip(_ count: Int) throws(DTLSEngineError) {
        guard count > 0 else { return }
        do { _ = try readBytes(count) } catch { throw .protocolFailure(reason: "byte skip failed: \(error)") }
    }
}

extension ByteWriter {
    @inline(__always)
    mutating func eWriteVector8(_ payload: [UInt8]) throws(DTLSEngineError) {
        do { try writeVector8(payload) } catch { throw .internalError(reason: "vector8 write failed: \(error)") }
    }

    @inline(__always)
    mutating func eWriteVector16(_ payload: [UInt8]) throws(DTLSEngineError) {
        do { try writeVector16(payload) } catch { throw .internalError(reason: "vector16 write failed: \(error)") }
    }
}
