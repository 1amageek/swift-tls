/// TLS 1.3 Extensions (RFC 8446 Section 4.2)
///
/// Extensions have the format:
/// ```
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```

import Foundation

// MARK: - Extension Type

/// TLS extension types (RFC 8446 Section 4.2)
public enum TLSExtensionType: UInt16, Sendable {
    case serverName = 0                     // SNI
    case supportedGroups = 10               // Supported elliptic curves
    case signatureAlgorithms = 13           // Supported signature algorithms
    case alpn = 16                          // Application-Layer Protocol Negotiation
    case preSharedKey = 41                  // Pre-shared key
    case earlyData = 42                     // Early data (0-RTT)
    case supportedVersions = 43             // TLS versions supported
    case pskKeyExchangeModes = 45           // PSK key exchange modes
    case keyShare = 51                      // Key share for (EC)DHE
    case transportParameters = 57       // Transport parameters (0x0039)
}

// MARK: - Message Context

/// Context for extension decoding — determines the wire format for
/// context-dependent extensions (key_share, supported_versions,
/// pre_shared_key, early_data).
public enum MessageContext: Sendable {
    case clientHello
    case serverHello
    case helloRetryRequest
    case encryptedExtensions
    case newSessionTicket
    case certificateRequest
}

// MARK: - Extension Value Protocol

/// Protocol for extension values
public protocol TLSExtensionValue: Sendable {
    static var extensionType: TLSExtensionType { get }
    func encode() -> Data
}

// MARK: - TLS Extension Enum

/// A TLS extension with its type and value
public enum TLSExtension: Sendable {
    case serverName(ServerNameExtension)
    case supportedGroups(SupportedGroupsExtension)
    case signatureAlgorithms(SignatureAlgorithmsExtension)
    case alpn(ALPNExtension)
    case preSharedKey(PreSharedKeyExtension)
    case earlyData(EarlyDataExtension)
    case supportedVersions(SupportedVersionsExtension)
    case pskKeyExchangeModes(PskKeyExchangeModesExtension)
    case keyShare(KeyShareExtension)
    case transportParameters(Data)
    case unknown(type: UInt16, data: Data)

    // MARK: - Properties

    /// The extension type
    public var extensionType: TLSExtensionType? {
        switch self {
        case .serverName: return .serverName
        case .supportedGroups: return .supportedGroups
        case .signatureAlgorithms: return .signatureAlgorithms
        case .alpn: return .alpn
        case .preSharedKey: return .preSharedKey
        case .earlyData: return .earlyData
        case .supportedVersions: return .supportedVersions
        case .pskKeyExchangeModes: return .pskKeyExchangeModes
        case .keyShare: return .keyShare
        case .transportParameters: return .transportParameters
        case .unknown: return nil
        }
    }

    /// The raw extension type value
    public var rawType: UInt16 {
        switch self {
        case .serverName: return TLSExtensionType.serverName.rawValue
        case .supportedGroups: return TLSExtensionType.supportedGroups.rawValue
        case .signatureAlgorithms: return TLSExtensionType.signatureAlgorithms.rawValue
        case .alpn: return TLSExtensionType.alpn.rawValue
        case .preSharedKey: return TLSExtensionType.preSharedKey.rawValue
        case .earlyData: return TLSExtensionType.earlyData.rawValue
        case .supportedVersions: return TLSExtensionType.supportedVersions.rawValue
        case .pskKeyExchangeModes: return TLSExtensionType.pskKeyExchangeModes.rawValue
        case .keyShare: return TLSExtensionType.keyShare.rawValue
        case .transportParameters: return TLSExtensionType.transportParameters.rawValue
        case .unknown(let type, _): return type
        }
    }

    /// Get the underlying value if it matches the expected type
    public var value: any TLSExtensionValue {
        switch self {
        case .serverName(let v): return v
        case .supportedGroups(let v): return v
        case .signatureAlgorithms(let v): return v
        case .alpn(let v): return v
        case .preSharedKey(let v): return v
        case .earlyData(let v): return v
        case .supportedVersions(let v): return v
        case .pskKeyExchangeModes(let v): return v
        case .keyShare(let v): return v
        case .transportParameters(let data): return TransportParametersExtension(data: data)
        case .unknown(let type, let data): return UnknownExtension(type: type, data: data)
        }
    }

    // MARK: - Encoding

    /// Encode the extension (type + length + data)
    public func encode() -> Data {
        let extensionData: Data
        switch self {
        case .serverName(let ext): extensionData = ext.encode()
        case .supportedGroups(let ext): extensionData = ext.encode()
        case .signatureAlgorithms(let ext): extensionData = ext.encode()
        case .alpn(let ext): extensionData = ext.encode()
        case .preSharedKey(let ext): extensionData = ext.encode()
        case .earlyData(let ext): extensionData = ext.encode()
        case .supportedVersions(let ext): extensionData = ext.encode()
        case .pskKeyExchangeModes(let ext): extensionData = ext.encode()
        case .keyShare(let ext): extensionData = ext.encode()
        case .transportParameters(let data): extensionData = data
        case .unknown(_, let data): extensionData = data
        }

        var writer = TLSWriter(capacity: 4 + extensionData.count)
        writer.writeUInt16(rawType)
        writer.writeVector16(extensionData)
        return writer.finish()
    }

    // MARK: - Decoding

    /// Decode an extension from a reader with default (ClientHello) context.
    /// Prefer `decode(from:context:)` when the message context is known.
    public static func decode(from reader: inout TLSReader) throws -> TLSExtension {
        try decode(from: &reader, context: .clientHello)
    }

    /// Decode an extension from a reader with explicit message context.
    ///
    /// Context-dependent extensions decode differently based on the message:
    /// - `key_share`: ClientHello (list), ServerHello (single entry), HRR (group only)
    /// - `supported_versions`: ClientHello (list), ServerHello (single version)
    /// - `pre_shared_key`: ClientHello (offered PSKs), ServerHello (selected identity)
    /// - `early_data`: ClientHello/EE (empty), NewSessionTicket (max_early_data_size)
    public static func decode(from reader: inout TLSReader, context: MessageContext) throws -> TLSExtension {
        let type = try reader.readUInt16()
        let data = try reader.readVector16()

        guard let extensionType = TLSExtensionType(rawValue: type) else {
            return .unknown(type: type, data: data)
        }

        return try decodeWithContext(extensionType: extensionType, data: data, context: context)
    }

    /// Decode multiple extensions from a Data blob with default (ClientHello) context.
    public static func decodeExtensions(from data: Data) throws -> [TLSExtension] {
        try decodeExtensions(from: data, context: .clientHello)
    }

    /// Decode multiple extensions from a Data blob with explicit context.
    ///
    /// RFC 8446 Section 4.2: "There MUST NOT be more than one extension
    /// of the same type in a given extension block."
    public static func decodeExtensions(from data: Data, context: MessageContext) throws -> [TLSExtension] {
        var reader = TLSReader(data: data)
        var extensions: [TLSExtension] = []
        var seenTypes: Set<UInt16> = []
        while reader.hasMore {
            let ext = try decode(from: &reader, context: context)
            guard seenTypes.insert(ext.rawType).inserted else {
                throw TLSHandshakeError.invalidExtension(
                    "Duplicate extension type: 0x\(String(ext.rawType, radix: 16))"
                )
            }
            extensions.append(ext)
        }
        return extensions
    }

    /// Core decode logic with message context.
    private static func decodeWithContext(
        extensionType: TLSExtensionType,
        data: Data,
        context: MessageContext
    ) throws -> TLSExtension {
        switch extensionType {
        case .serverName:
            return .serverName(try ServerNameExtension.decode(from: data))
        case .supportedGroups:
            return .supportedGroups(try SupportedGroupsExtension.decode(from: data))
        case .signatureAlgorithms:
            return .signatureAlgorithms(try SignatureAlgorithmsExtension.decode(from: data))
        case .alpn:
            return .alpn(try ALPNExtension.decode(from: data))
        case .pskKeyExchangeModes:
            return .pskKeyExchangeModes(try PskKeyExchangeModesExtension.decode(from: data))
        case .transportParameters:
            return .transportParameters(data)

        // Context-dependent extensions:
        case .preSharedKey:
            switch context {
            case .serverHello:
                return .preSharedKey(try PreSharedKeyExtension.decodeServerHello(from: data))
            default:
                return .preSharedKey(try PreSharedKeyExtension.decodeClientHello(from: data))
            }

        case .earlyData:
            switch context {
            case .newSessionTicket:
                return .earlyData(try EarlyDataExtension.decodeNewSessionTicket(from: data))
            default:
                return .earlyData(try EarlyDataExtension.decodeEmpty(from: data))
            }

        case .supportedVersions:
            switch context {
            case .serverHello, .helloRetryRequest:
                return .supportedVersions(.serverHello(try SupportedVersionsServerHello.decode(from: data)))
            default:
                return .supportedVersions(.clientHello(try SupportedVersionsClientHello.decode(from: data)))
            }

        case .keyShare:
            switch context {
            case .helloRetryRequest:
                return .keyShare(.helloRetryRequest(try KeyShareHelloRetryRequest.decode(from: data)))
            case .serverHello:
                return .keyShare(.serverHello(try KeyShareServerHello.decode(from: data)))
            default:
                return .keyShare(.clientHello(try KeyShareClientHello.decode(from: data)))
            }
        }
    }
}

// MARK: - Convenience Factory Methods

extension TLSExtension {
    /// Create a supported_versions extension for ClientHello
    public static func supportedVersionsClient(_ versions: [UInt16]) -> TLSExtension {
        .supportedVersions(.clientHello(SupportedVersionsClientHello(versions: versions)))
    }

    /// Create a supported_versions extension for ServerHello
    public static func supportedVersionsServer(_ version: UInt16) -> TLSExtension {
        .supportedVersions(.serverHello(SupportedVersionsServerHello(selectedVersion: version)))
    }

    /// Create a key_share extension for ClientHello
    public static func keyShareClient(_ entries: [KeyShareEntry]) -> TLSExtension {
        .keyShare(.clientHello(KeyShareClientHello(clientShares: entries)))
    }

    /// Create a key_share extension for ServerHello
    public static func keyShareServer(_ entry: KeyShareEntry) -> TLSExtension {
        .keyShare(.serverHello(KeyShareServerHello(serverShare: entry)))
    }

    /// Create an ALPN extension
    public static func alpnProtocols(_ protocols: [String]) -> TLSExtension {
        .alpn(ALPNExtension(protocols: protocols))
    }

    /// Create a supported_groups extension
    public static func supportedGroupsList(_ groups: [NamedGroup]) -> TLSExtension {
        .supportedGroups(SupportedGroupsExtension(namedGroups: groups))
    }

    /// Create a signature_algorithms extension
    public static func signatureAlgorithmsList(_ schemes: [SignatureScheme]) -> TLSExtension {
        .signatureAlgorithms(SignatureAlgorithmsExtension(supportedSignatureAlgorithms: schemes))
    }

    /// Create a psk_key_exchange_modes extension
    public static func pskKeyExchangeModesList(_ modes: [PskKeyExchangeMode]) -> TLSExtension {
        .pskKeyExchangeModes(PskKeyExchangeModesExtension(keModes: modes))
    }

    /// Create an early_data extension for ClientHello
    public static func earlyDataClient() -> TLSExtension {
        .earlyData(.clientHello)
    }

    /// Create an early_data extension for EncryptedExtensions
    public static func earlyDataServer() -> TLSExtension {
        .earlyData(.encryptedExtensions)
    }

    /// Create a pre_shared_key extension for ClientHello
    public static func preSharedKeyClient(_ offered: OfferedPsks) -> TLSExtension {
        .preSharedKey(.clientHello(offered))
    }

    /// Create a pre_shared_key extension for ServerHello
    public static func preSharedKeyServer(selectedIdentity: UInt16) -> TLSExtension {
        .preSharedKey(.serverHello(SelectedPsk(selectedIdentity: selectedIdentity)))
    }
}

// MARK: - Unknown Extension

/// Placeholder for unknown extensions
public struct UnknownExtension: TLSExtensionValue {
    public static var extensionType: TLSExtensionType { fatalError("Unknown extension has no type") }
    public let type: UInt16
    public let data: Data

    public func encode() -> Data { data }
}

// MARK: - Transport Parameters Extension

/// Transport parameters extension (type 0x0039)
///
/// Used by protocols like QUIC that embed transport-specific parameters
/// in the TLS handshake via extensions.
public struct TransportParametersExtension: TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .transportParameters }
    public let data: Data

    public func encode() -> Data { data }
}
