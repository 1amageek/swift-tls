/// Legacy `Data`-based `TLSReader`/`TLSWriter` codec bridges for the moved DTLS
/// wire types.
///
/// The DTLS record codec and handshake handler in this adapter still drive the
/// historical `Data`-backed `TLSReader`/`TLSWriter` (defined in `TLSCore`). The
/// Embedded-clean core types encode/decode over `P2PCoreBytes`
/// `ByteReader`/`ByteWriter`. These thin overloads bridge the two cursors by
/// reading the exact fixed-size span from the legacy reader and decoding it via the
/// core, or by encoding via the core and appending the bytes to the legacy writer.

import Foundation
import TLSCore
import DTLSWireCore
import P2PCoreBytes

// MARK: - DTLSVersion (legacy cursor)

extension DTLSVersion {
    /// Encode to a `Data`-based `TLSWriter`.
    public func encode(writer: inout TLSWriter) {
        var w = ByteWriter()
        encode(writer: &w)
        writer.writeBytes(Data(w.finishArray()))
    }

    /// Decode from a `Data`-based `TLSReader` (consumes 2 bytes).
    public static func decode(reader: inout TLSReader) throws -> DTLSVersion {
        let bytes = [UInt8](try reader.readBytes(2))
        var r = ByteReader(bytes)
        do { return try decode(reader: &r) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - DTLSCipherSuite (legacy cursor)

extension DTLSCipherSuite {
    /// Encode to a `Data`-based `TLSWriter`.
    public func encode(writer: inout TLSWriter) {
        var w = ByteWriter()
        encode(writer: &w)
        writer.writeBytes(Data(w.finishArray()))
    }

    /// Decode from a `Data`-based `TLSReader` (consumes 2 bytes).
    public static func decode(reader: inout TLSReader) throws -> DTLSCipherSuite {
        let bytes = [UInt8](try reader.readBytes(2))
        var r = ByteReader(bytes)
        do { return try decode(reader: &r) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - DTLSHandshakeHeader (legacy cursor + Data helpers)

extension DTLSHandshakeHeader {
    /// Encode the 12-byte header to a `Data`-based `TLSWriter`.
    public func encode(writer: inout TLSWriter) {
        var w = ByteWriter()
        do { try encode(writer: &w) } catch {
            fatalError("DTLS handshake header encoding exceeded a wire length bound: \(error)")
        }
        writer.writeBytes(Data(w.finishArray()))
    }

    /// Decode the 12-byte header from a `Data`-based `TLSReader`.
    public static func decode(reader: inout TLSReader) throws -> DTLSHandshakeHeader {
        let bytes = [UInt8](try reader.readBytes(DTLSHandshakeHeader.headerSize))
        var r = ByteReader(bytes)
        do { return try decode(reader: &r) } catch { try error.rethrowUnwrapped() }
    }

    /// Encode a complete handshake message (header + body) — `Data` in/out.
    public static func encodeMessage(
        type: DTLSHandshakeType,
        messageSeq: UInt16,
        body: Data
    ) -> Data {
        encodeDTLSData { try encodeMessage(type: type, messageSeq: messageSeq, body: [UInt8](body)) }
    }

    /// Fragment a handshake message — `Data` in, `[Data]` out.
    public static func fragmentMessage(
        type: DTLSHandshakeType,
        messageSeq: UInt16,
        body: Data,
        maxFragmentSize: Int = 1200
    ) -> [Data] {
        let fragments: [[UInt8]]
        do {
            fragments = try fragmentMessage(
                type: type,
                messageSeq: messageSeq,
                body: [UInt8](body),
                maxFragmentSize: maxFragmentSize
            )
        } catch {
            fatalError("DTLS handshake fragmentation exceeded a wire length bound: \(error)")
        }
        return fragments.map { Data($0) }
    }
}
