/// DTLS 1.2 Key Schedule
///
/// Derives master_secret from pre_master_secret, then expands to key_block
/// containing client/server write keys and IVs.
///
/// RFC 5246 Section 8.1:
///   master_secret = PRF(pre_master_secret, "master secret",
///                       ClientHello.random + ServerHello.random)[0..47]
///
///   key_block = PRF(master_secret, "key expansion",
///                   server_random + client_random)

import Foundation

/// Key block derived from master secret
public struct DTLSKeyBlock: Sendable {
    /// Client write encryption key
    public let clientWriteKey: Data
    /// Server write encryption key
    public let serverWriteKey: Data
    /// Client write IV (fixed part, 4 bytes for AES-GCM)
    public let clientWriteIV: Data
    /// Server write IV (fixed part, 4 bytes for AES-GCM)
    public let serverWriteIV: Data
}

/// DTLS 1.2 key schedule for deriving traffic keys
public struct DTLSKeySchedule: Sendable {
    private let cipherSuite: DTLSCipherSuite
    private var masterSecret: Data?
    private var clientRandom: Data?
    private var serverRandom: Data?

    public init(cipherSuite: DTLSCipherSuite) {
        self.cipherSuite = cipherSuite
    }

    /// Derive master_secret from pre_master_secret and randoms
    /// - Parameters:
    ///   - preMasterSecret: The pre-master secret from key exchange
    ///   - clientRandom: 32-byte client random
    ///   - serverRandom: 32-byte server random
    public mutating func deriveMasterSecret(
        preMasterSecret: Data,
        clientRandom: Data,
        serverRandom: Data
    ) {
        let seed = clientRandom + serverRandom
        let prf: Data
        switch cipherSuite.hashAlgorithm {
        case .sha256:
            prf = PRF.compute(
                secret: preMasterSecret,
                label: "master secret",
                seed: seed,
                length: 48
            )
        case .sha384:
            prf = PRF.computeSHA384(
                secret: preMasterSecret,
                label: "master secret",
                seed: seed,
                length: 48
            )
        }
        self.masterSecret = prf
        self.clientRandom = clientRandom
        self.serverRandom = serverRandom
    }

    /// Derive key block from master secret
    /// - Returns: Client/server write keys and IVs
    /// - Throws: If master secret has not been derived
    public func deriveKeyBlock() throws -> DTLSKeyBlock {
        guard let masterSecret, let clientRandom, let serverRandom else {
            throw DTLSError.invalidState("Master secret not derived")
        }

        // key_block uses server_random + client_random (reversed from master_secret)
        let seed = serverRandom + clientRandom

        // Total key material needed:
        // client_write_key + server_write_key + client_write_IV + server_write_IV
        let keyLength = cipherSuite.keyLength
        let ivLength = cipherSuite.fixedIVLength
        let totalLength = 2 * keyLength + 2 * ivLength

        let keyBlock: Data
        switch cipherSuite.hashAlgorithm {
        case .sha256:
            keyBlock = PRF.compute(
                secret: masterSecret,
                label: "key expansion",
                seed: seed,
                length: totalLength
            )
        case .sha384:
            keyBlock = PRF.computeSHA384(
                secret: masterSecret,
                label: "key expansion",
                seed: seed,
                length: totalLength
            )
        }

        var offset = 0
        let clientWriteKey = keyBlock[offset..<offset + keyLength]
        offset += keyLength
        let serverWriteKey = keyBlock[offset..<offset + keyLength]
        offset += keyLength
        let clientWriteIV = keyBlock[offset..<offset + ivLength]
        offset += ivLength
        let serverWriteIV = keyBlock[offset..<offset + ivLength]

        return DTLSKeyBlock(
            clientWriteKey: Data(clientWriteKey),
            serverWriteKey: Data(serverWriteKey),
            clientWriteIV: Data(clientWriteIV),
            serverWriteIV: Data(serverWriteIV)
        )
    }

    /// Compute verify_data for Finished message
    /// - Parameters:
    ///   - label: "client finished" or "server finished"
    ///   - handshakeHash: Hash of all handshake messages
    /// - Returns: 12-byte verify_data
    public func computeVerifyData(label: String, handshakeHash: Data) throws -> Data {
        guard let masterSecret else {
            throw DTLSError.invalidState("Master secret not derived")
        }

        switch cipherSuite.hashAlgorithm {
        case .sha256:
            return PRF.compute(
                secret: masterSecret,
                label: label,
                seed: handshakeHash,
                length: 12
            )
        case .sha384:
            return PRF.computeSHA384(
                secret: masterSecret,
                label: label,
                seed: handshakeHash,
                length: 12
            )
        }
    }
}
