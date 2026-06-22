/// `Data`-based convenience surface for the moved DTLS wire message types.
///
/// Each moved type's Embedded-clean core exposes `encodeBytes() throws -> [UInt8]`
/// and `decode(from: [UInt8])`. This file restores the historical non-throwing
/// `encode() -> Data` / `decode(from: Data)` API plus `Data`-accepting
/// convenience initializers (including the random-generating ones that draw from
/// the host CSPRNG), so existing callers and tests compile unchanged.
///
/// The non-throwing `encode()` shims call the throwing core encoder; the only error
/// it can raise is a wire-length overflow (a payload exceeding its length-prefix
/// width), which is a programmer-contract violation that the pre-extraction code
/// expressed as an integer-conversion trap. We surface it as a `fatalError` (a
/// loud, non-silent crash) rather than swallowing it — there is no valid fallback
/// for an unencodable message.

import Foundation
import P2PCoreBytes
import TLSCore

// MARK: - DTLSClientHello

extension DTLSClientHello {
    /// Creates a ClientHello from `Data` fields.
    public init(
        clientVersion: DTLSVersion = .v1_2,
        random: Data,
        sessionID: Data = Data(),
        cookie: Data = Data(),
        cipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        supportedGroups: [NamedGroup] = [.secp256r1],
        signatureAlgorithms: [SignatureScheme] = [.ecdsa_secp256r1_sha256]
    ) {
        self.init(
            clientVersion: clientVersion,
            random: [UInt8](random),
            sessionID: [UInt8](sessionID),
            cookie: [UInt8](cookie),
            cipherSuites: cipherSuites,
            supportedGroups: supportedGroups,
            signatureAlgorithms: signatureAlgorithms
        )
    }

    /// Creates a ClientHello with a `[UInt8]` random and a `Data` cookie.
    ///
    /// Supports call sites that reuse a decoded ClientHello's `[UInt8]` random
    /// together with a cookie extracted from a `Data`-based HelloVerifyRequest.
    public init(
        clientVersion: DTLSVersion = .v1_2,
        random: [UInt8],
        cookie: Data,
        cipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        supportedGroups: [NamedGroup] = [.secp256r1],
        signatureAlgorithms: [SignatureScheme] = [.ecdsa_secp256r1_sha256]
    ) {
        self.init(
            clientVersion: clientVersion,
            random: random,
            sessionID: [],
            cookie: [UInt8](cookie),
            cipherSuites: cipherSuites,
            supportedGroups: supportedGroups,
            signatureAlgorithms: signatureAlgorithms
        )
    }

    /// Creates a ClientHello, generating the random from the host CSPRNG when not
    /// supplied.
    ///
    /// - Throws: A secure-random error if `random` is not supplied and the system
    ///   CSPRNG fails. RNG failure is never swallowed; the caller decides how to
    ///   handle it.
    public init(
        clientVersion: DTLSVersion = .v1_2,
        random: Data? = nil,
        sessionID: Data = Data(),
        cookie: Data = Data(),
        cipherSuites: [DTLSCipherSuite] = [.ecdheEcdsaWithAes128GcmSha256],
        supportedGroups: [NamedGroup] = [.secp256r1],
        signatureAlgorithms: [SignatureScheme] = [.ecdsa_secp256r1_sha256]
    ) throws {
        let randomBytes: [UInt8]
        if let random {
            randomBytes = [UInt8](random)
        } else {
            randomBytes = [UInt8](try secureRandomBytes(count: 32))
        }
        self.init(
            clientVersion: clientVersion,
            random: randomBytes,
            sessionID: [UInt8](sessionID),
            cookie: [UInt8](cookie),
            cipherSuites: cipherSuites,
            supportedGroups: supportedGroups,
            signatureAlgorithms: signatureAlgorithms
        )
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> DTLSClientHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - DTLSServerHello

extension DTLSServerHello {
    /// Creates a ServerHello from `Data` fields.
    public init(
        serverVersion: DTLSVersion = .v1_2,
        random: Data,
        sessionID: Data = Data(),
        cipherSuite: DTLSCipherSuite
    ) {
        self.init(
            serverVersion: serverVersion,
            random: [UInt8](random),
            sessionID: [UInt8](sessionID),
            cipherSuite: cipherSuite
        )
    }

    /// Creates a ServerHello, generating the random from the host CSPRNG when not
    /// supplied.
    ///
    /// - Throws: A secure-random error if `random` is not supplied and the system
    ///   CSPRNG fails. RNG failure is surfaced, never swallowed.
    public init(
        serverVersion: DTLSVersion = .v1_2,
        random: Data? = nil,
        sessionID: Data = Data(),
        cipherSuite: DTLSCipherSuite
    ) throws {
        let randomBytes: [UInt8]
        if let random {
            randomBytes = [UInt8](random)
        } else {
            randomBytes = [UInt8](try secureRandomBytes(count: 32))
        }
        self.init(
            serverVersion: serverVersion,
            random: randomBytes,
            sessionID: [UInt8](sessionID),
            cipherSuite: cipherSuite
        )
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> DTLSServerHello {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - CertificateMessage

extension CertificateMessage {
    /// Creates a Certificate message from `Data` certificate chain.
    public init(certificates: [Data]) {
        self.init(certificates: certificates.map { [UInt8]($0) })
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> CertificateMessage {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }

    /// All certificate data as `Data` values.
    public var certificatesData: [Data] { certificates.map { Data($0) } }
}

// MARK: - ServerKeyExchange

extension ServerKeyExchange {
    /// Creates a ServerKeyExchange from `Data` fields.
    public init(
        namedGroup: NamedGroup,
        publicKey: Data,
        signatureScheme: SignatureScheme,
        signature: Data
    ) {
        self.init(
            namedGroup: namedGroup,
            publicKey: [UInt8](publicKey),
            signatureScheme: signatureScheme,
            signature: [UInt8](signature)
        )
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ServerKeyExchange {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - ClientKeyExchange

extension ClientKeyExchange {
    /// Creates a ClientKeyExchange from a `Data` public key.
    public init(publicKey: Data) {
        self.init(publicKey: [UInt8](publicKey))
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ClientKeyExchange {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - CertificateVerify

extension CertificateVerify {
    /// Creates a CertificateVerify from a `Data` signature.
    public init(signatureScheme: SignatureScheme, signature: Data) {
        self.init(signatureScheme: signatureScheme, signature: [UInt8](signature))
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> CertificateVerify {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - DTLSFinished

extension DTLSFinished {
    /// Creates a Finished message from `Data` verify_data.
    public init(verifyData: Data) {
        self.init(verifyData: [UInt8](verifyData))
    }

    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> DTLSFinished {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

// MARK: - ServerHelloDone / ChangeCipherSpec

extension ServerHelloDone {
    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ServerHelloDone {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}

extension ChangeCipherSpec {
    public func encode() -> Data { encodeDTLSData { try encodeBytes() } }
    public static func decode(from data: Data) throws -> ChangeCipherSpec {
        do { return try decode(from: [UInt8](data)) } catch { try error.rethrowUnwrapped() }
    }
}
