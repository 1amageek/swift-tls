/// DTLS 1.2 Key Schedule (RFC 5246 §8.1), Embedded-clean.
///
/// Derives `master_secret` from the pre-master secret and the handshake randoms,
/// then expands `key_block` (client/server write keys + IVs) and `verify_data`
/// (Finished) through ``DTLSPRF`` over the crypto MAC seam.
///
/// ```
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
/// key_block     = PRF(master_secret, "key expansion",
///                     server_random + client_random)
/// verify_data   = PRF(master_secret, finished_label, handshake_hash)[0..11]
/// ```
///
/// A single value type; the negotiated cipher suite selects the hash. The
/// `master secret` is held privately and out-of-order use throws
/// ``DTLSWireCore/DTLSError`` (no silent fallback).
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = TLSFoundationProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import DTLSWireCore

/// Key block derived from the DTLS 1.2 master secret (raw `[UInt8]`).
public struct DTLSKeyBlockCore: Sendable, Equatable {
    public let clientWriteKey: [UInt8]
    public let serverWriteKey: [UInt8]
    public let clientWriteIV: [UInt8]
    public let serverWriteIV: [UInt8]

    public init(
        clientWriteKey: [UInt8],
        serverWriteKey: [UInt8],
        clientWriteIV: [UInt8],
        serverWriteIV: [UInt8]
    ) {
        self.clientWriteKey = clientWriteKey
        self.serverWriteKey = serverWriteKey
        self.clientWriteIV = clientWriteIV
        self.serverWriteIV = serverWriteIV
    }
}

/// The DTLS 1.2 key schedule over the crypto MAC seam.
public struct DTLSKeyScheduleCore<C: CryptoProvider>: Sendable {
    public let cipherSuite: DTLSCipherSuite
    private var masterSecret: [UInt8]?
    private var clientRandom: [UInt8]?
    private var serverRandom: [UInt8]?

    public init(cipherSuite: DTLSCipherSuite) {
        self.cipherSuite = cipherSuite
        self.masterSecret = nil
        self.clientRandom = nil
        self.serverRandom = nil
    }

    /// Whether the master secret has been derived.
    public var hasMasterSecret: Bool { masterSecret != nil }

    /// `master_secret = PRF(pre_master_secret, "master secret",
    ///   client_random + server_random)[0..47]`.
    public mutating func deriveMasterSecret(
        preMasterSecret: [UInt8],
        clientRandom: [UInt8],
        serverRandom: [UInt8]
    ) {
        var seed = [UInt8]()
        seed.reserveCapacity(clientRandom.count + serverRandom.count)
        seed.append(contentsOf: clientRandom)
        seed.append(contentsOf: serverRandom)
        self.masterSecret = DTLSPRF<C>.compute(
            secret: preMasterSecret,
            label: "master secret",
            seed: seed,
            length: 48,
            hash: cipherSuite.hashAlgorithm
        )
        self.clientRandom = clientRandom
        self.serverRandom = serverRandom
    }

    /// `key_block = PRF(master_secret, "key expansion",
    ///   server_random + client_random)` split into the write keys and IVs.
    public func deriveKeyBlock() throws(DTLSError) -> DTLSKeyBlockCore {
        guard let masterSecret, let clientRandom, let serverRandom else {
            throw DTLSError.invalidState("Master secret not derived")
        }

        // key_block uses server_random + client_random (reversed from master_secret).
        var seed = [UInt8]()
        seed.reserveCapacity(serverRandom.count + clientRandom.count)
        seed.append(contentsOf: serverRandom)
        seed.append(contentsOf: clientRandom)

        let keyLength = cipherSuite.keyLength
        let ivLength = cipherSuite.fixedIVLength
        let totalLength = 2 * keyLength + 2 * ivLength

        let keyBlock = DTLSPRF<C>.compute(
            secret: masterSecret,
            label: "key expansion",
            seed: seed,
            length: totalLength,
            hash: cipherSuite.hashAlgorithm
        )

        var offset = 0
        let clientWriteKey = Array(keyBlock[offset..<offset + keyLength])
        offset += keyLength
        let serverWriteKey = Array(keyBlock[offset..<offset + keyLength])
        offset += keyLength
        let clientWriteIV = Array(keyBlock[offset..<offset + ivLength])
        offset += ivLength
        let serverWriteIV = Array(keyBlock[offset..<offset + ivLength])

        return DTLSKeyBlockCore(
            clientWriteKey: clientWriteKey,
            serverWriteKey: serverWriteKey,
            clientWriteIV: clientWriteIV,
            serverWriteIV: serverWriteIV
        )
    }

    /// `verify_data = PRF(master_secret, label, handshake_hash)[0..11]`.
    public func computeVerifyData(
        label: String,
        handshakeHash: [UInt8]
    ) throws(DTLSError) -> [UInt8] {
        guard let masterSecret else {
            throw DTLSError.invalidState("Master secret not derived")
        }
        return DTLSPRF<C>.compute(
            secret: masterSecret,
            label: label,
            seed: handshakeHash,
            length: 12,
            hash: cipherSuite.hashAlgorithm
        )
    }
}
