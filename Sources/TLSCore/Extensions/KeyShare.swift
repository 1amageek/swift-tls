/// TLS 1.3 Key Share Extension (RFC 8446 Section 4.2.8)
///
/// In ClientHello:
/// ```
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
/// ```
///
/// In ServerHello:
/// ```
/// struct {
///     KeyShareEntry server_share;
/// } KeyShareServerHello;
/// ```
///
/// KeyShareEntry:
/// ```
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
/// ```

import Foundation

// MARK: - Key Share Entry

/// A key share entry containing a named group and public key
public struct KeyShareEntry: Sendable {
    /// The named group (curve) for this key share
    public let group: NamedGroup

    /// The public key bytes
    public let keyExchange: Data

    public init(group: NamedGroup, keyExchange: Data) {
        self.group = group
        self.keyExchange = keyExchange
    }

    public func encode() -> Data {
        var writer = TLSWriter(capacity: 4 + keyExchange.count)
        writer.writeUInt16(group.rawValue)
        writer.writeVector16(keyExchange)
        return writer.finish()
    }

    public static func decode(from reader: inout TLSReader) throws -> KeyShareEntry {
        let groupValue = try reader.readUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw TLSDecodeError.invalidFormat("Unknown named group: \(groupValue)")
        }
        let keyExchange = try reader.readVector16()
        return KeyShareEntry(group: group, keyExchange: keyExchange)
    }
}

// MARK: - Key Share Extension (wrapper)

/// Key share extension (can be client or server variant)
public enum KeyShareExtension: Sendable, TLSExtensionValue {
    case clientHello(KeyShareClientHello)
    case serverHello(KeyShareServerHello)
    case helloRetryRequest(KeyShareHelloRetryRequest)

    public static var extensionType: TLSExtensionType { .keyShare }

    public func encode() -> Data {
        switch self {
        case .clientHello(let ext): return ext.encode()
        case .serverHello(let ext): return ext.encode()
        case .helloRetryRequest(let ext): return ext.encode()
        }
    }

    /// The handshake message context a key_share extension was carried in. The wire
    /// format of a key_share is ambiguous without this context, so the caller MUST
    /// supply it rather than relying on a byte-pattern heuristic.
    public enum MessageContext: Sendable {
        case clientHello
        case serverHello
        case helloRetryRequest
    }

    /// Decode a key_share extension using the EXPLICIT message context.
    ///
    /// The three on-wire variants (ClientHello list, ServerHello single entry, and
    /// HelloRetryRequest bare group) cannot be reliably distinguished by inspecting
    /// the bytes — a previous heuristic both guessed wrong on edge cases and trapped
    /// on a sliced `Data` (absolute indexing). The context removes the guess.
    public static func decode(from data: Data, context: MessageContext) throws -> KeyShareExtension {
        switch context {
        case .clientHello:
            return .clientHello(try KeyShareClientHello.decode(from: data))
        case .serverHello:
            return .serverHello(try KeyShareServerHello.decode(from: data))
        case .helloRetryRequest:
            return .helloRetryRequest(try KeyShareHelloRetryRequest.decode(from: data))
        }
    }

    public static func decodeClientHello(from data: Data) throws -> KeyShareClientHello {
        try KeyShareClientHello.decode(from: data)
    }

    public static func decodeServerHello(from data: Data) throws -> KeyShareServerHello {
        try KeyShareServerHello.decode(from: data)
    }
}

// MARK: - Client Hello Variant

/// Key share extension for ClientHello
public struct KeyShareClientHello: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .keyShare }

    /// List of key shares offered by the client
    public let clientShares: [KeyShareEntry]

    public init(clientShares: [KeyShareEntry]) {
        self.clientShares = clientShares
    }

    public func encode() -> Data {
        var entriesData = Data()
        for entry in clientShares {
            entriesData.append(entry.encode())
        }

        var writer = TLSWriter(capacity: 2 + entriesData.count)
        writer.writeVector16(entriesData)
        return writer.finish()
    }

    public static func decode(from data: Data) throws -> KeyShareClientHello {
        var reader = TLSReader(data: data)
        let entriesData = try reader.readVector16()

        var entries: [KeyShareEntry] = []
        var entryReader = TLSReader(data: entriesData)
        while entryReader.hasMore {
            entries.append(try KeyShareEntry.decode(from: &entryReader))
        }

        return KeyShareClientHello(clientShares: entries)
    }

    /// Find a key share for a specific group
    public func keyShare(for group: NamedGroup) -> KeyShareEntry? {
        clientShares.first { $0.group == group }
    }
}

// MARK: - Server Hello Variant

/// Key share extension for ServerHello
public struct KeyShareServerHello: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .keyShare }

    /// The server's selected key share
    public let serverShare: KeyShareEntry

    public init(serverShare: KeyShareEntry) {
        self.serverShare = serverShare
    }

    public func encode() -> Data {
        serverShare.encode()
    }

    public static func decode(from data: Data) throws -> KeyShareServerHello {
        var reader = TLSReader(data: data)
        let entry = try KeyShareEntry.decode(from: &reader)
        return KeyShareServerHello(serverShare: entry)
    }
}

// MARK: - Hello Retry Request Variant

/// Key share extension for HelloRetryRequest (only contains selected group)
public struct KeyShareHelloRetryRequest: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .keyShare }

    /// The group the server wants the client to use
    public let selectedGroup: NamedGroup

    public init(selectedGroup: NamedGroup) {
        self.selectedGroup = selectedGroup
    }

    public func encode() -> Data {
        var writer = TLSWriter(capacity: 2)
        writer.writeUInt16(selectedGroup.rawValue)
        return writer.finish()
    }

    public static func decode(from data: Data) throws -> KeyShareHelloRetryRequest {
        var reader = TLSReader(data: data)
        let groupValue = try reader.readUInt16()
        guard let group = NamedGroup(rawValue: groupValue) else {
            throw TLSDecodeError.invalidFormat("Unknown named group: \(groupValue)")
        }
        return KeyShareHelloRetryRequest(selectedGroup: group)
    }
}
