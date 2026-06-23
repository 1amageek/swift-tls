/// TLS 1.2 / DTLS 1.2 PRF — Foundation adapter over the Embedded-clean core.
///
/// Restores the historical `Data`-based `PRF.compute` / `PRF.computeSHA384` surface
/// (used by the existing test suite) and delegates to
/// ``DTLSHandshakeCore/DTLSPRF`` specialised at `C = TLSFoundationProvider`, so the
/// output is byte-identical to the pre-extraction swift-crypto implementation.
///
/// RFC 5246 Section 5:
///   PRF(secret, label, seed) = P_hash(secret, label + seed)

import Foundation
import TLSCore
import DTLSWireCore
import DTLSHandshakeCore

/// TLS 1.2 Pseudo-Random Function
public enum PRF: Sendable {

    /// Compute PRF with SHA-256.
    public static func compute(
        secret: Data,
        label: String,
        seed: Data,
        length: Int
    ) -> Data {
        Data(DTLSPRF<TLSFoundationProvider>.compute(
            secret: [UInt8](secret),
            label: label,
            seed: [UInt8](seed),
            length: length,
            hash: .sha256
        ))
    }

    /// Compute PRF with SHA-384 (for AES-256-GCM suites).
    public static func computeSHA384(
        secret: Data,
        label: String,
        seed: Data,
        length: Int
    ) -> Data {
        Data(DTLSPRF<TLSFoundationProvider>.compute(
            secret: [UInt8](secret),
            label: label,
            seed: [UInt8](seed),
            length: length,
            hash: .sha384
        ))
    }
}
