/// TLS 1.3 Transcript Hash (RFC 8446 Section 4.4.1), Embedded-clean.
///
/// Maintains a running hash of all handshake messages routed through the
/// ``P2PCoreCrypto/HashFunction`` seam:
/// ```
/// Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
/// ```
///
/// The cipher suite selects SHA-256 (`C.SHA256`) or SHA-384 (`C.SHA384`); both
/// are carried in a closed enum so a single value type covers either hash
/// without `any`. `currentHash()` snapshots the running hasher and finalizes the
/// copy, because ``P2PCoreCrypto/HashFunction/finalize()`` is single-use
/// (`consuming`).
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto. Generic over the
/// crypto provider; the adapter specialises at `C = TLSCryptoProvider`.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore

/// A running TLS 1.3 transcript hash over the crypto seam.
public struct TLSTranscriptHash<C: CryptoProvider>: Sendable {

    /// The active hash state, branched by cipher-suite hash.
    private enum Hasher: Sendable {
        case sha256(C.SHA256)
        case sha384(C.SHA384)
    }

    private var hasher: Hasher
    private var messageCount: Int

    /// Digest length in bytes (32 for SHA-256, 48 for SHA-384).
    public let hashLength: Int

    // MARK: - Initialization

    /// Creates an empty transcript for `cipherSuite`'s hash.
    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            self.hasher = .sha384(C.SHA384())
            self.hashLength = C.SHA384.digestLength
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            self.hasher = .sha256(C.SHA256())
            self.hashLength = C.SHA256.digestLength
        }
        self.messageCount = 0
    }

    private init(hasher: Hasher, messageCount: Int, hashLength: Int) {
        self.hasher = hasher
        self.messageCount = messageCount
        self.hashLength = hashLength
    }

    // MARK: - Update

    /// Feeds a complete handshake message (including its 4-byte header) into the
    /// transcript and bumps the message count.
    public mutating func update(with message: Span<UInt8>) {
        absorb(message)
        messageCount += 1
    }

    /// Feeds raw bytes into the transcript without bumping the message count.
    public mutating func updateRaw(with data: Span<UInt8>) {
        absorb(data)
    }

    private mutating func absorb(_ data: Span<UInt8>) {
        switch hasher {
        case .sha256(var h):
            h.update(data)
            hasher = .sha256(h)
        case .sha384(var h):
            h.update(data)
            hasher = .sha384(h)
        }
    }

    // MARK: - Hash Value

    /// The current transcript hash (a snapshot of the running hasher).
    public func currentHash() -> [UInt8] {
        switch hasher {
        case .sha256(let h):
            let copy = h
            return copy.finalize()
        case .sha384(let h):
            let copy = h
            return copy.finalize()
        }
    }

    /// Number of handshake messages absorbed.
    public var count: Int { messageCount }

    // MARK: - Special Operations

    /// Builds a transcript starting from a synthetic `message_hash` of a prior
    /// ClientHello (RFC 8446 §4.4.1, HelloRetryRequest path):
    /// ```
    /// Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    ///     Hash(message_hash || 00 00 Hash.length || Hash(ClientHello1) || ...)
    /// ```
    public static func fromMessageHash(
        clientHello1Hash: [UInt8],
        cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256
    ) -> TLSTranscriptHash<C> {
        var transcript = TLSTranscriptHash<C>(cipherSuite: cipherSuite)

        var writer = ByteWriter()
        writer.writeUInt8(HandshakeType.messageHash.rawValue)
        writer.writeUInt8(0x00)
        writer.writeUInt8(0x00)
        writer.writeUInt8(UInt8(truncatingIfNeeded: clientHello1Hash.count))
        writer.writeBytes(clientHello1Hash)
        let synthetic = writer.finishArray()

        transcript.update(with: synthetic.span)
        return transcript
    }

    /// Returns an independent copy of the running transcript state.
    public func copy() -> TLSTranscriptHash<C> {
        TLSTranscriptHash<C>(hasher: hasher, messageCount: messageCount, hashLength: hashLength)
    }
}
