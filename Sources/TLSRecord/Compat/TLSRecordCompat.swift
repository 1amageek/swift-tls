/// Foundation `Data` compatibility layer over the Embedded-clean `TLSRecordCore`.
///
/// `TLSRecordCore` expresses the TLS record-layer codec over `[UInt8]` so it can
/// build under Embedded Swift. This adapter file restores the historical
/// `Data`-based public surface that the Mutex-bound record layer
/// (`TLSRecordCryptor` / `TLSRecordLayer` / `TLSConnection`) and the existing
/// test suite bind to. It is pure bridging: `Data <-> [UInt8]` conversions over
/// the core codec. No new framing logic lives here.

import Foundation
@_exported import TLSRecordCore

// MARK: - TLSRecord (Data convenience init)

extension TLSRecord {
    /// Creates a record from a `Data` fragment.
    ///
    /// The core stores `fragment` as `[UInt8]`; this restores the historical
    /// `Data`-accepting initializer for callers that still build records from
    /// `Data`.
    public init(contentType: TLSContentType, fragment: Data) {
        self.init(contentType: contentType, fragment: [UInt8](fragment))
    }
}

// MARK: - TLSRecordCodec (Data API)

extension TLSRecordCodec {
    /// Encode a plaintext record, `Data` in / `Data` out.
    public static func encodePlaintext(type: TLSContentType, data: Data) -> Data {
        Data(encodePlaintext(type: type, data: [UInt8](data)))
    }

    /// Encode a ciphertext record, `Data` in / `Data` out.
    public static func encodeCiphertext(_ ciphertext: Data) -> Data {
        Data(encodeCiphertext([UInt8](ciphertext)))
    }

    /// Decode a single TLS record from a `Data` buffer.
    ///
    /// The core decoder throws ``TLSRecordError`` (typed); this wrapper widens it
    /// to the untyped `throws` boundary so existing `try` call sites and
    /// `#expect(throws: TLSRecordError.self)` tests catch it directly.
    public static func decode(from buffer: Data) throws -> (TLSRecord, Int)? {
        try decode(from: [UInt8](buffer))
    }
}
