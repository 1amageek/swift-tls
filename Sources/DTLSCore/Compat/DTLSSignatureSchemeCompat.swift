/// `Data`-boundary `SignatureScheme` (hash, signature) byte helpers.
///
/// `DTLSWireCore` carries `SignatureScheme.from(hash:signature:)` as an
/// internal typed-throws helper used by its own codecs. This adapter re-exposes it
/// publicly with the historical untyped-`throws` signature (throwing the unwrapped
/// `DTLSError`), so callers and the existing test suite catch `DTLSError` directly.

import TLSCore
import TLSWireCore
import DTLSWireCore

extension SignatureScheme {
    /// Hash algorithm byte for TLS 1.2 signature.
    public var hashByte: UInt8 {
        UInt8(rawValue >> 8)
    }

    /// Signature algorithm byte for TLS 1.2 signature.
    public var signatureByte: UInt8 {
        UInt8(rawValue & 0xFF)
    }

    /// Construct from hash + signature algorithm bytes.
    ///
    /// Rejects an unknown (hash, signature) pair rather than silently defaulting to
    /// ECDSA-P256-SHA256 — a silent default would let a peer's advertised algorithm
    /// be misinterpreted, breaking signature verification semantics.
    public static func from(hash: UInt8, signature: UInt8) throws -> SignatureScheme {
        let value = UInt16(hash) << 8 | UInt16(signature)
        guard let scheme = SignatureScheme(rawValue: value) else {
            throw DTLSError.invalidServerKeyExchange(
                "Unknown signature scheme 0x\(String(value, radix: 16))"
            )
        }
        return scheme
    }
}
