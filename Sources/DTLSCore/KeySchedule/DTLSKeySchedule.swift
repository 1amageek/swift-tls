/// DTLS 1.2 Key Schedule — Foundation adapter over the Embedded-clean core.
///
/// Restores the historical `Data`-based `DTLSKeySchedule` / `DTLSKeyBlock` public
/// surface (used by `DTLSConnection` and the existing test suite) and delegates the
/// actual derivation to ``DTLSHandshakeCore/DTLSKeyScheduleCore`` specialised at
/// `C = TLSCryptoProvider`, so the master secret, key block, and Finished
/// verify_data are byte-identical to the pre-extraction implementation.
///
/// RFC 5246 Section 8.1:
///   master_secret = PRF(pre_master_secret, "master secret",
///                       ClientHello.random + ServerHello.random)[0..47]
///   key_block     = PRF(master_secret, "key expansion",
///                       server_random + client_random)

import Foundation
import TLSCore
import DTLSWireCore
import DTLSHandshakeCore

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

    public init(
        clientWriteKey: Data,
        serverWriteKey: Data,
        clientWriteIV: Data,
        serverWriteIV: Data
    ) {
        self.clientWriteKey = clientWriteKey
        self.serverWriteKey = serverWriteKey
        self.clientWriteIV = clientWriteIV
        self.serverWriteIV = serverWriteIV
    }

    /// Bridge a core key block ([UInt8]) into the Data-based adapter type.
    init(core: DTLSKeyBlockCore) {
        self.clientWriteKey = Data(core.clientWriteKey)
        self.serverWriteKey = Data(core.serverWriteKey)
        self.clientWriteIV = Data(core.clientWriteIV)
        self.serverWriteIV = Data(core.serverWriteIV)
    }
}

/// DTLS 1.2 key schedule for deriving traffic keys
public struct DTLSKeySchedule: Sendable {
    private var core: DTLSKeyScheduleCore<TLSCryptoProvider>

    public init(cipherSuite: DTLSCipherSuite) {
        self.core = DTLSKeyScheduleCore<TLSCryptoProvider>(cipherSuite: cipherSuite)
    }

    /// Derive master_secret from pre_master_secret and randoms
    public mutating func deriveMasterSecret(
        preMasterSecret: Data,
        clientRandom: Data,
        serverRandom: Data
    ) {
        core.deriveMasterSecret(
            preMasterSecret: [UInt8](preMasterSecret),
            clientRandom: [UInt8](clientRandom),
            serverRandom: [UInt8](serverRandom)
        )
    }

    /// Derive key block from master secret
    /// - Throws: `DTLSError` if the master secret has not been derived
    public func deriveKeyBlock() throws -> DTLSKeyBlock {
        do {
            return DTLSKeyBlock(core: try core.deriveKeyBlock())
        } catch {
            throw error
        }
    }

    /// Compute verify_data for Finished message
    /// - Throws: `DTLSError` if the master secret has not been derived
    public func computeVerifyData(label: String, handshakeHash: Data) throws -> Data {
        do {
            return Data(try core.computeVerifyData(label: label, handshakeHash: [UInt8](handshakeHash)))
        } catch {
            throw error
        }
    }
}
