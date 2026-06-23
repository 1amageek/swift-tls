/// DTLS 1.2 handshake transcript hash, Embedded-clean.
///
/// DTLS 1.2 (unlike TLS 1.3) hashes the *full accumulated* handshake-message
/// buffer at several points (CertificateVerify, Finished). The legacy adapter kept
/// the raw bytes and called `SHA256.hash(data:)` / `SHA384.hash(data:)` one-shot,
/// so this helper does the same over the ``P2PCoreCrypto/HashFunction`` seam — the
/// running buffer is owned by the FSM and the hash is recomputed on demand. Byte-
/// for-byte identical to the swift-crypto path.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto.

import P2PCoreBytes
import P2PCoreCrypto
import DTLSWireCore

/// One-shot transcript hash of the accumulated handshake-message buffer.
public enum DTLSTranscript<C: CryptoProvider> {

    /// `Hash(messages)` for the suite's hash (SHA-256 default, SHA-384 for the
    /// AES-256-GCM suite), matching the legacy `computeHandshakeHash`.
    public static func hash(
        messages: [UInt8],
        cipherSuite: DTLSCipherSuite?
    ) -> [UInt8] {
        switch cipherSuite?.hashAlgorithm {
        case .sha384:
            return C.SHA384.hash(messages.span)
        default:
            return C.SHA256.hash(messages.span)
        }
    }
}
