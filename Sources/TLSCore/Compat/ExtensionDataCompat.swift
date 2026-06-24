/// `Data`-based convenience surface for the moved TLS extension and alert types.
///
/// Restores the historical non-throwing `encode() -> Data` / `decode(from: Data)`
/// API and `Data`-accepting initializers on the Embedded-clean extension types,
/// plus the `any TLSExtensionValue` accessor used by the adapter's
/// `findExtension`. This file is Foundation-only adapter glue.

import Foundation
import TLSWireCore
import P2PCoreBytes

// MARK: - Encode helper

@inline(__always)
private func encodeData(_ body: () throws -> [UInt8]) -> Data {
    do {
        return Data(try body())
    } catch {
        fatalError("TLS extension encoding exceeded a wire length bound: \(error)")
    }
}

// MARK: - TLSAlert (Data)

extension TLSAlert {
    /// Encode the alert as 2 bytes of `Data`.
    public func encode() -> Data { Data(encodeBytes()) }

    /// Encode as a complete TLS record (`Data`).
    public func encodeAsRecord() -> Data { Data(encodeAsRecordBytes()) }

    /// Decode an alert from `Data`.
    public static func decode(from data: Data) throws -> TLSAlert {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

// MARK: - TLSExtension (Data)

extension TLSExtension {
    /// The `transportParameters` payload as `Data`, when applicable.
    public static func transportParameters(_ data: Data) -> TLSExtension {
        .transportParameters([UInt8](data))
    }

    /// An `unknown` extension from `Data`.
    public static func unknown(type: UInt16, data: Data) -> TLSExtension {
        .unknown(type: type, data: [UInt8](data))
    }

    /// Encode the extension (type + length + data) as `Data`.
    public func encode() -> Data { encodeData { try encodeBytes() } }

    /// Decode an extension from a `Data`-backed reader.
    public static func decode(from reader: inout TLSReader) throws -> TLSExtension {
        try decode(from: &reader, context: .clientHello)
    }

    /// Decode an extension from a `Data`-backed reader with explicit context.
    public static func decode(from reader: inout TLSReader, context: MessageContext) throws -> TLSExtension {
        let type = try reader.readUInt16()
        let data = try reader.readVector16()
        guard TLSExtensionType(rawValue: type) != nil else {
            return .unknown(type: type, data: data)
        }
        // Re-encode the single extension as a one-element extension block and
        // decode through the core's `[UInt8]` path so the context-dependent
        // variant selection stays in one place.
        var w = ByteWriter(reservingCapacity: 4 + data.count)
        w.writeUInt16(type)
        do {
            try w.writeVector16([UInt8](data))
        } catch {
            throw TLSDecodeError.invalidFormat("extension data exceeds length bound")
        }
        let decoded = try decodeExtensions(from: Data(w.finishArray()), context: context)
        guard let first = decoded.first else {
            throw TLSDecodeError.invalidFormat("extension block decoded to no extensions")
        }
        return first
    }

    /// Decode multiple extensions from a `Data` blob (default ClientHello context).
    public static func decodeExtensions(from data: Data) throws -> [TLSExtension] {
        do { return try decodeExtensions(from: [UInt8](data), context: .clientHello) } catch { try error.rethrowUnwrapped() }

    }

    /// Decode multiple extensions from a `Data` blob with explicit context.
    public static func decodeExtensions(from data: Data, context: MessageContext) throws -> [TLSExtension] {
        do { return try decodeExtensions(from: [UInt8](data), context: context) } catch { try error.rethrowUnwrapped() }

    }
}

/// Returns the underlying extension value as an existential.
///
/// Adapter-only: the Embedded-clean core deliberately omits this accessor (it
/// would require an `any` existential). Used by `findExtension`.
func extensionValue(_ ext: TLSExtension) -> any TLSExtensionValue {
    switch ext {
    case .serverName(let v): return v
    case .supportedGroups(let v): return v
    case .signatureAlgorithms(let v): return v
    case .alpn(let v): return v
    case .clientCertificateType(let v): return v
    case .serverCertificateType(let v): return v
    case .preSharedKey(let v): return v
    case .earlyData(let v): return v
    case .supportedVersions(let v): return v
    case .pskKeyExchangeModes(let v): return v
    case .keyShare(let v): return v
    case .transportParameters(let data): return TransportParametersExtension(data: data)
    case .unknown(let type, let data): return UnknownExtensionValue(type: type, data: data)
    }
}

/// Adapter placeholder conforming to `TLSExtensionValue` for unknown extensions.
struct UnknownExtensionValue: TLSExtensionValue {
    static var extensionType: TLSExtensionType { .transportParameters }  // unused; unknown has no type
    let type: UInt16
    let data: [UInt8]
    func encodeBytes() -> [UInt8] { data }
}

// MARK: - Per-extension Data encode/decode

extension ALPNExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ALPNExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension ServerNameExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ServerNameExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension SupportedGroupsExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedGroupsExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension SignatureAlgorithmsExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SignatureAlgorithmsExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension SupportedVersionsExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data, context: MessageContext) throws -> SupportedVersionsExtension {
        do { return try decode(from: [UInt8](data), context: context) } catch { try error.rethrowUnwrapped() }

    }
}

extension SupportedVersionsClientHello {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedVersionsClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension SupportedVersionsServerHello {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> SupportedVersionsServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension PskKeyExchangeModesExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> PskKeyExchangeModesExtension {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension ClientCertificateTypeExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decodeOffered(from data: Data) throws -> ClientCertificateTypeExtension {
        do { return try decodeOffered(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
    public static func decodeSelected(from data: Data) throws -> ClientCertificateTypeExtension {
        do { return try decodeSelected(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension ServerCertificateTypeExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decodeOffered(from data: Data) throws -> ServerCertificateTypeExtension {
        do { return try decodeOffered(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
    public static func decodeSelected(from data: Data) throws -> ServerCertificateTypeExtension {
        do { return try decodeSelected(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension EarlyDataExtension {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decodeEmpty(from data: Data) throws -> EarlyDataExtension {
        do { return try decodeEmpty(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
    public static func decodeNewSessionTicket(from data: Data) throws -> EarlyDataExtension {
        do { return try decodeNewSessionTicket(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension EndOfEarlyData {
    public func encode() -> Data { Data(encodeBytes()) }
    public func encodeMessage() -> Data { Data(encodeMessageBytes()) }
    public static func decode(from data: Data) throws -> EndOfEarlyData {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

// MARK: - KeyShare (Data)

extension KeyShareEntry {
    /// Creates a key share entry from a `Data` public key.
    public init(group: NamedGroup, keyExchange: Data) {
        self.init(group: group, keyExchange: [UInt8](keyExchange))
    }

    /// The public key bytes as `Data`.
    public var keyExchangeData: Data { Data(keyExchange) }

    public func encode() -> Data { encodeData { try encodeBytes() } }

    /// Decode from a `Data`-backed reader, advancing the reader's cursor.
    public static func decode(from reader: inout TLSReader) throws -> KeyShareEntry {
        let groupValue = try reader.readUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw TLSDecodeError.invalidFormat("Unknown named group: \(groupValue)")
        }
        let keyExchange = try reader.readVector16()
        return KeyShareEntry(group: group, keyExchange: [UInt8](keyExchange))
    }
}

extension KeyShareExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data, context: MessageContext) throws -> KeyShareExtension {
        do { return try decode(from: [UInt8](data), context: context) } catch { try error.rethrowUnwrapped() }

    }
    public static func decodeClientHello(from data: Data) throws -> KeyShareClientHello {
        do { return try decodeClientHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
    public static func decodeServerHello(from data: Data) throws -> KeyShareServerHello {
        do { return try decodeServerHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension KeyShareClientHello {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> KeyShareClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension KeyShareServerHello {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> KeyShareServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension KeyShareHelloRetryRequest {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decode(from data: Data) throws -> KeyShareHelloRetryRequest {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

// MARK: - PreSharedKey (Data)

extension PskIdentity {
    /// Creates a PSK identity from a `Data` identity.
    public init(identity: Data, obfuscatedTicketAge: UInt32) {
        self.init(identity: [UInt8](identity), obfuscatedTicketAge: obfuscatedTicketAge)
    }

    /// The PSK identity as `Data`.
    public var identityData: Data { Data(identity) }

    public func encode() -> Data { encodeData { try encodeBytes() } }

    /// Decode from a `Data`-backed reader, advancing the reader's cursor.
    public static func decode(from reader: inout TLSReader) throws -> PskIdentity {
        let identity = try reader.readVector16()
        let obfuscatedAge = try reader.readUInt32()
        return PskIdentity(identity: [UInt8](identity), obfuscatedTicketAge: obfuscatedAge)
    }
}

extension OfferedPsks {
    /// Creates offered PSKs from binders whose elements are any byte sequence
    /// (e.g. `[Data]`). Forwards to the core `[[UInt8]]` initializer. An empty
    /// `binders: []` literal resolves to the core initializer's default rather
    /// than this generic overload, so it stays unambiguous.
    public init<S: Sequence>(identities: [PskIdentity], binders: [S]) where S.Element == UInt8 {
        self.init(identities: identities, binders: binders.map { Array($0) })
    }

    /// The binders as `Data` values.
    public var bindersData: [Data] { binders.map { Data($0) } }

    /// The encoded identities part for binder computation as `Data`.
    public var encodedIdentitiesData: Data { Data(encodedIdentities) }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> OfferedPsks {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension SelectedPsk {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decode(from data: Data) throws -> SelectedPsk {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension PreSharedKeyExtension {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public static func decodeClientHello(from data: Data) throws -> PreSharedKeyExtension {
        do { return try decodeClientHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
    public static func decodeServerHello(from data: Data) throws -> PreSharedKeyExtension {
        do { return try decodeServerHello(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension TransportParametersExtension {
    /// Creates from `Data`.
    public init(data: Data) {
        self.init(data: [UInt8](data))
    }

    public func encode() -> Data { Data(encodeBytes()) }
}
