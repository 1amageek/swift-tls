/// TLS 1.3 record-protection traffic keys (RFC 8446 §7.3), Embedded-clean.
///
/// Derives the AEAD `key` and `iv` from a traffic secret via
/// `HKDF-Expand-Label`:
/// ```
/// key = HKDF-Expand-Label(Secret, "key", "", key_length)
/// iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)
/// ```
/// Both are raw `[UInt8]` (the IV is kept as bytes for XOR with the record
/// sequence number). Generic over the crypto provider seam.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore

/// AEAD key + IV derived from a TLS 1.3 traffic secret.
public struct TLSTrafficKeys: Sendable {
    /// The AEAD encryption key (16 bytes for AES-128, 32 for AES-256/ChaCha20).
    public let key: [UInt8]

    /// The 12-byte AEAD IV.
    public let iv: [UInt8]

    /// Derives the (key, iv) pair from `secret` for `cipherSuite`.
    public static func derive<C: CryptoProvider>(
        secret: Span<UInt8>,
        cipherSuite: CipherSuite,
        provider: C.Type = C.self
    ) throws(TLSKeyScheduleCoreError) -> TLSTrafficKeys {
        let emptyContext = [UInt8]()
        let key = try TLSHkdf<C>.expandLabel(
            secret: secret,
            label: "key",
            context: emptyContext.span,
            length: cipherSuite.keyLength,
            cipherSuite: cipherSuite
        )
        let iv = try TLSHkdf<C>.expandLabel(
            secret: secret,
            label: "iv",
            context: emptyContext.span,
            length: cipherSuite.ivLength,
            cipherSuite: cipherSuite
        )
        return TLSTrafficKeys(key: key, iv: iv)
    }

    private init(key: [UInt8], iv: [UInt8]) {
        self.key = key
        self.iv = iv
    }
}
