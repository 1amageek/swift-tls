/// TLS 1.3 Transcript Hash (RFC 8446 Section 4.4.1) — Foundation adapter.
///
/// The running-hash logic now lives in the Embedded-clean
/// `TLSCryptoCore.TLSTranscriptHash<C>`, routed through the
/// `P2PCoreCrypto.HashFunction` seam. This adapter preserves the existing
/// `Data`-based API by specialising the core at `C = TLSProvider` and
/// bridging `Data` ↔ `[UInt8]` at the boundary.
///
/// For TLS 1.3:
/// ```
/// Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
/// ```

import Foundation
import Crypto
import P2PCoreBytes
import TLSWireCore
import TLSCryptoCore

// MARK: - Transcript Hash

/// Maintains a running hash of handshake messages (Foundation adapter).
/// Supports both SHA-256 and SHA-384 based on cipher suite.
public struct TranscriptHash: Sendable {
    private var core: TLSCryptoCore.TLSTranscriptHash<TLSProvider>

    /// Hash output length in bytes
    public var hashLength: Int { core.hashLength }

    // MARK: - Initialization

    /// Initialize with default SHA-256
    public init() {
        self.core = TLSCryptoCore.TLSTranscriptHash<TLSProvider>()
    }

    /// Initialize with specific cipher suite
    public init(cipherSuite: CipherSuite) {
        self.core = TLSCryptoCore.TLSTranscriptHash<TLSProvider>(cipherSuite: cipherSuite)
    }

    /// Internal init wrapping a core value (for copy / fromMessageHash)
    private init(core: TLSCryptoCore.TLSTranscriptHash<TLSProvider>) {
        self.core = core
    }

    /// The underlying Embedded-clean core value.
    ///
    /// Used by the handshake state machine to hand ownership of the running
    /// transcript to `TLSHandshakeCore.TLSClientAuthMachine` at the
    /// EncryptedExtensions boundary. After the hand-off the adapter must not
    /// update this transcript again (the core owns it from there).
    var coreValue: TLSCryptoCore.TLSTranscriptHash<TLSProvider> { core }

    // MARK: - Update

    /// Update the transcript with a handshake message
    /// - Parameter message: The complete handshake message (including 4-byte header)
    public mutating func update(with message: Data) {
        let bytes = [UInt8](message)
        core.update(with: bytes.span)
    }

    /// Update the transcript with raw data
    /// - Parameter data: Raw data to hash
    public mutating func updateRaw(with data: Data) {
        let bytes = [UInt8](data)
        core.updateRaw(with: bytes.span)
    }

    // MARK: - Hash Value

    /// Get the current transcript hash value
    /// - Returns: The hash (32 bytes for SHA-256, 48 bytes for SHA-384)
    public func currentHash() -> Data {
        Data(core.currentHash())
    }

    /// Number of messages hashed
    public var count: Int { core.count }

    // MARK: - Special Operations

    /// Create a transcript hash from a message hash (for HelloRetryRequest)
    /// Per RFC 8446 Section 4.4.1:
    /// ```
    /// Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    ///     Hash(message_hash ||     /* Handshake type */
    ///          00 00 Hash.length ||  /* Uint24 length */
    ///          Hash(ClientHello1) || /* Hash */
    ///          HelloRetryRequest || ... || Mn)
    /// ```
    public static func fromMessageHash(
        clientHello1Hash: Data,
        cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256
    ) -> TranscriptHash {
        let core = TLSCryptoCore.TLSTranscriptHash<TLSProvider>.fromMessageHash(
            clientHello1Hash: [UInt8](clientHello1Hash),
            cipherSuite: cipherSuite
        )
        return TranscriptHash(core: core)
    }

    /// Create a copy of the transcript hash
    public func copy() -> TranscriptHash {
        TranscriptHash(core: core.copy())
    }
}

// MARK: - Transcript Hash with SHA-384

/// Transcript hash using SHA-384 (for TLS_AES_256_GCM_SHA384)
public struct TranscriptHashSHA384: Sendable {
    private var hasher: SHA384
    private var messageCount: Int

    public init() {
        self.hasher = SHA384()
        self.messageCount = 0
    }

    public mutating func update(with message: Data) {
        hasher.update(data: message)
        messageCount += 1
    }

    public mutating func updateRaw(with data: Data) {
        hasher.update(data: data)
    }

    public func currentHash() -> Data {
        let copy = hasher
        return Data(copy.finalize())
    }

    public static var hashLength: Int { 48 }

    public var count: Int { messageCount }

    public func copy() -> TranscriptHashSHA384 {
        var newTranscript = TranscriptHashSHA384()
        newTranscript.hasher = self.hasher
        newTranscript.messageCount = self.messageCount
        return newTranscript
    }
}
