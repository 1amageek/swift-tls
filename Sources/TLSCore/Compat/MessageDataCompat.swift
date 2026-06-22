/// `Data`-based convenience surface for the moved TLS wire message types.
///
/// Each moved type's Embedded-clean core exposes `encodeBytes() throws -> [UInt8]`
/// and `decode(from: [UInt8])`. This file restores the historical non-throwing
/// `encode() -> Data` / `decode(from: Data)` API plus `Data`-accepting
/// convenience initializers, so existing callers and tests compile unchanged.
///
/// The non-throwing `encode()` shims call the throwing core encoder; the only
/// error it can raise is a wire-length overflow (a payload exceeding its
/// length-prefix width), which is a programmer-contract violation that the
/// pre-extraction code expressed as an integer-conversion trap. We surface it as
/// a `fatalError` (a loud, non-silent crash) rather than swallowing it — there is
/// no valid fallback for an unencodable message.

import Foundation
import P2PCoreBytes

// MARK: - Encode helper

/// Runs a throwing byte encoder and returns `Data`, trapping on the
/// impossible-for-valid-input wire-length overflow (matching the historical
/// trapping behaviour of the `Data`-based writer).
@inline(__always)
private func encodeData(_ body: () throws -> [UInt8]) -> Data {
    do {
        return Data(try body())
    } catch {
        fatalError("TLS message encoding exceeded a wire length bound: \(error)")
    }
}

// MARK: - HandshakeMessage / TLSConstants

extension TLSConstants {
    /// HelloRetryRequest magic random value as `Data`.
    public static var helloRetryRequestRandomData: Data {
        Data(helloRetryRequestRandom)
    }
}

// MARK: - ClientHello

extension ClientHello {
    /// Creates a ClientHello from `Data` fields.
    public init(
        random: Data,
        legacySessionID: Data = Data(),
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension]
    ) throws {
        try self.init(
            random: [UInt8](random),
            legacySessionID: [UInt8](legacySessionID),
            cipherSuites: cipherSuites,
            extensions: extensions
        )
    }

    /// Creates a ClientHello with generated random.
    public init(
        legacySessionID: Data = Data(),
        cipherSuites: [CipherSuite] = [.tls_aes_128_gcm_sha256],
        extensions: [TLSExtension]
    ) throws {
        let random = try secureRandomBytes(count: TLSConstants.randomLength)
        try self.init(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensions
        )
    }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { encodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> ClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }

    /// Find an extension by type (RFC 7250 / generic accessor).
    public func findExtension<T: TLSExtensionValue>(_ type: T.Type) -> T? {
        for ext in extensions {
            if let value = extensionValue(ext) as? T {
                return value
            }
        }
        return nil
    }
}

// MARK: - ServerHello

extension ServerHello {
    /// Creates a ServerHello from `Data` fields.
    public init(
        random: Data,
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) throws {
        try self.init(
            random: [UInt8](random),
            legacySessionIDEcho: [UInt8](legacySessionIDEcho),
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }

    /// Creates a ServerHello with a `[UInt8]` random and `Data` session-id echo.
    ///
    /// Supports call sites that pass the `[UInt8]` HelloRetryRequest sentinel
    /// (`TLSConstants.helloRetryRequestRandom`) together with a `Data` echo.
    public init(
        random: [UInt8],
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) throws {
        try self.init(
            random: random,
            legacySessionIDEcho: [UInt8](legacySessionIDEcho),
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }

    /// Creates a ServerHello with generated random.
    public init(
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) throws {
        let random = try secureRandomBytes(count: TLSConstants.randomLength)
        try self.init(
            random: random,
            legacySessionIDEcho: legacySessionIDEcho,
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }

    /// Creates a HelloRetryRequest with `Data` session-id echo.
    public static func helloRetryRequest(
        legacySessionIDEcho: Data,
        cipherSuite: CipherSuite,
        extensions: [TLSExtension]
    ) throws -> ServerHello {
        try helloRetryRequest(
            legacySessionIDEcho: [UInt8](legacySessionIDEcho),
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { encodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> ServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }

    /// Find an extension by type.
    public func findExtension<T: TLSExtensionValue>(_ type: T.Type) -> T? {
        for ext in extensions {
            if let value = extensionValue(ext) as? T {
                return value
            }
        }
        return nil
    }
}

// MARK: - Certificate

extension CertificateEntry {
    /// Creates a certificate entry from `Data`.
    public init(certData: Data, extensions: [TLSExtension] = []) {
        self.init(certData: [UInt8](certData), extensions: extensions)
    }

    /// The certificate data as `Data`.
    public var certDataValue: Data { Data(certData) }

    public func encode() -> Data { encodeData { try encodeBytes() } }
}

extension Certificate {
    /// Creates from explicit entries with a `Data` request context.
    public init(certificateRequestContext: Data = Data(), certificateList: [CertificateEntry]) {
        self.init(
            certificateRequestContext: [UInt8](certificateRequestContext),
            certificateList: certificateList
        )
    }

    /// Creates from raw DER certificate `Data` values.
    public init(certificateRequestContext: Data = Data(), certificates: [Data]) {
        self.init(
            certificateRequestContext: [UInt8](certificateRequestContext),
            certificates: certificates.map { [UInt8]($0) }
        )
    }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { encodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> Certificate {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }

    /// The leaf certificate as `Data`.
    public var leafCertificateData: Data? { leafCertificate.map { Data($0) } }

    /// All certificate data as `Data` values.
    public var certificatesData: [Data] { certificates.map { Data($0) } }
}

// MARK: - CertificateVerify

extension CertificateVerify {
    /// Creates a CertificateVerify from a `Data` signature.
    public init(algorithm: SignatureScheme, signature: Data) {
        self.init(algorithm: algorithm, signature: [UInt8](signature))
    }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { encodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> CertificateVerify {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }

    /// Constructs the content to be signed, returning `Data`.
    public static func constructSignatureContent(
        transcriptHash: Data,
        isServer: Bool
    ) -> Data {
        Data(constructSignatureContentBytes(transcriptHash: [UInt8](transcriptHash), isServer: isServer))
    }
}

// MARK: - Finished / KeyUpdate

extension Finished {
    /// Creates a Finished message from `Data` verify data.
    public init(verifyData: Data) {
        self.init(verifyData: [UInt8](verifyData))
    }

    public func encode() -> Data { Data(encodeBytes()) }
    public func encodeAsHandshake() -> Data { Data(encodeAsHandshakeBytes()) }
    public static func decode(from data: Data, hashLength: Int = TLSConstants.verifyDataLength) throws -> Finished {
        do { return try decode(from: [UInt8](data), hashLength: hashLength) } catch { try error.rethrowUnwrapped() }

    }

    /// Verify against expected `Data`.
    public func verify(expected: Data) -> Bool {
        verify(expected: [UInt8](expected))
    }
}

extension KeyUpdate {
    public func encode() -> Data { Data(encodeBytes()) }
    public func encodeAsHandshake() -> Data { Data(encodeAsHandshakeBytes()) }
    public static func decode(from data: Data) throws -> KeyUpdate {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

// MARK: - EncryptedExtensions

extension EncryptedExtensions {
    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { encodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> EncryptedExtensions {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }

    /// Transport parameters as `Data`.
    public var transportParametersData: Data? { transportParameters.map { Data($0) } }

    /// Find an extension by type.
    public func findExtension<T: TLSExtensionValue>(_ type: T.Type) -> T? {
        for ext in extensions {
            if let value = extensionValue(ext) as? T {
                return value
            }
        }
        return nil
    }
}

// MARK: - CertificateRequest

extension CertificateRequest {
    /// Creates a CertificateRequest from a `Data` request context.
    public init(certificateRequestContext: Data, extensions: [TLSExtension] = []) {
        self.init(
            certificateRequestContext: [UInt8](certificateRequestContext),
            extensions: extensions
        )
    }

    /// Creates a CertificateRequest with default signature algorithms and a `Data` context.
    public static func withDefaultSignatureAlgorithms(
        certificateRequestContext: Data
    ) -> CertificateRequest {
        withDefaultSignatureAlgorithms(certificateRequestContext: [UInt8](certificateRequestContext))
    }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeAsHandshake() -> Data { encodeData { try encodeAsHandshakeBytes() } }
    public static func decode(from data: Data) throws -> CertificateRequest {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

// MARK: - NewSessionTicket / EarlyDataIndication

extension NewSessionTicket {
    /// Creates a NewSessionTicket from `Data` fields.
    public init(
        ticketLifetime: UInt32,
        ticketAgeAdd: UInt32,
        ticketNonce: Data,
        ticket: Data,
        extensions: [TLSExtension] = []
    ) {
        self.init(
            ticketLifetime: ticketLifetime,
            ticketAgeAdd: ticketAgeAdd,
            ticketNonce: [UInt8](ticketNonce),
            ticket: [UInt8](ticket),
            extensions: extensions
        )
    }

    public func encode() -> Data { encodeData { try encodeBytes() } }
    public func encodeMessage() -> Data { encodeData { try encodeMessageBytes() } }
    public static func decode(from data: Data) throws -> NewSessionTicket {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}

extension EarlyDataIndication {
    public func encode() -> Data { Data(encodeBytes()) }
    public static func decode(from data: Data) throws -> EarlyDataIndication {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }

    }
}
