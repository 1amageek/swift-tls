/// PSK binder computation (RFC 8446 Section 4.2.11.2).
///
/// Depends on Crypto (HKDF/HMAC) and `SessionTicketData` (Date), so it stays in
/// the `TLSCore` adapter; the pure `PskIdentity`/`OfferedPsks` wire types live in
/// `TLSWireCore`.

import Foundation
import TLSWireCore
import Crypto

// MARK: - PskIdentity convenience init (Date / SessionTicketData)

extension PskIdentity {
    /// Create from a session ticket.
    public init(ticket: SessionTicketData, at now: Date = Date()) {
        self.init(
            identity: [UInt8](ticket.ticket),
            obfuscatedTicketAge: ticket.obfuscatedAge(at: now)
        )
    }
}

// MARK: - PSK Binder Computation

/// Helper for computing PSK binders
public struct PSKBinderHelper: Sendable {
    /// The cipher suite (determines hash function)
    public let cipherSuite: CipherSuite

    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        self.cipherSuite = cipherSuite
    }

    /// Compute the binder value
    /// - Parameters:
    ///   - key: The binder key (SymmetricKey)
    ///   - transcriptHash: Hash of ClientHello up to (but not including) binders
    /// - Returns: The binder value
    public func binder(
        forKey key: SymmetricKey,
        transcriptHash: Data
    ) -> Data {
        // finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
        let finishedKey = hkdfExpandLabel(
            secret: key,
            label: "finished",
            context: Data(),
            length: hashLength
        )

        // binder = HMAC(finished_key, Transcript-Hash(Truncate(ClientHello)))
        return hmac(key: finishedKey, data: transcriptHash)
    }

    /// Verify a binder
    public func isValidBinder(
        forKey key: SymmetricKey,
        transcriptHash: Data,
        expected: Data
    ) -> Bool {
        let computed = binder(forKey: key, transcriptHash: transcriptHash)
        return constantTimeEqual(computed, expected)
    }

    // MARK: - Private Helpers

    private var hashLength: Int {
        cipherSuite.hashLength
    }

    private func hkdfExpandLabel(secret: SymmetricKey, label: String, context: Data, length: Int) -> SymmetricKey {
        let fullLabel = "tls13 " + label
        let labelBytes = Data(fullLabel.utf8)

        var hkdfLabel = Data()
        hkdfLabel.append(UInt8(length >> 8))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(labelBytes.count))
        hkdfLabel.append(labelBytes)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)

        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            return HKDF<SHA384>.expand(
                pseudoRandomKey: secret,
                info: hkdfLabel,
                outputByteCount: length
            )
        default:
            return HKDF<SHA256>.expand(
                pseudoRandomKey: secret,
                info: hkdfLabel,
                outputByteCount: length
            )
        }
    }

    private func hmac(key: SymmetricKey, data: Data) -> Data {
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            let mac = HMAC<SHA384>.authenticationCode(for: data, using: key)
            return Data(mac)
        default:
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
            return Data(mac)
        }
    }

}
