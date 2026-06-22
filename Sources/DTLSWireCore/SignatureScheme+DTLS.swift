/// DTLS 1.2 (hash, signature) algorithm byte helpers for ``SignatureScheme``.
///
/// TLS 1.2 / DTLS 1.2 encode a signature algorithm as a 2-byte pair
/// (HashAlgorithm, SignatureAlgorithm), which maps onto the TLS 1.3
/// ``SignatureScheme`` 16-bit code point. These helpers convert between the two
/// representations on the DTLS wire path.

import TLSWireCore

extension SignatureScheme {
    /// Hash algorithm byte for TLS 1.2 signature
    var hashByte: UInt8 {
        UInt8(rawValue >> 8)
    }

    /// Signature algorithm byte for TLS 1.2 signature
    var signatureByte: UInt8 {
        UInt8(rawValue & 0xFF)
    }

    /// Construct from hash + signature algorithm bytes.
    ///
    /// Rejects an unknown (hash, signature) pair rather than silently defaulting to
    /// ECDSA-P256-SHA256 — a silent default would let a peer's advertised algorithm
    /// be misinterpreted, breaking signature verification semantics.
    static func from(hash: UInt8, signature: UInt8) throws(DTLSWireError) -> SignatureScheme {
        let value = UInt16(hash) << 8 | UInt16(signature)
        guard let scheme = SignatureScheme(rawValue: value) else {
            throw DTLSWireError.dtls(.invalidServerKeyExchange(
                "Unknown signature scheme 0x\(String(value, radix: 16))"
            ))
        }
        return scheme
    }
}
