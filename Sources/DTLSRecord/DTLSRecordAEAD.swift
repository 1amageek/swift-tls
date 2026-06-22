/// Host (non-Embedded) concrete `AEAD` seam conformance for DTLS 1.2 record
/// protection (RFC 5288 — AES-GCM for TLS).
///
/// The Embedded-clean `DTLSRecordCore.DTLSRecordProtector<C, A>` is generic over
/// `A: P2PCoreCrypto.AEAD`. The host adapter specialises it with this
/// swift-crypto–backed AES-GCM AEAD, byte-identical to the AEAD behavior swift-tls
/// shipped before the seam refactor (the legacy `DTLSRecordCryptor`'s
/// `AES.GCM.seal/open`).
///
/// DTLS 1.2 mandates AES-GCM (the only suite swift-tls supports for DTLS records),
/// so this is a single algorithm rather than a suite switch.
///
/// AEAD-open failure throws ``P2PCoreCrypto/CryptoError/authenticationFailure``
/// (the protector then collapses it to `decryptionFailed`) — no silent fallback.

import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// A swift-crypto AES-GCM AEAD bound to one key, for DTLS 1.2 record protection.
public struct DTLSRecordAEAD: P2PCoreCrypto.AEAD {
    public static let nonceLength = 12
    public static let tagLength   = 16

    private let key: SymmetricKey

    /// Builds the AEAD from raw key bytes.
    public init(key: [UInt8]) {
        self.key = SymmetricKey(data: Data(key))
    }

    public func seal(
        _ plaintext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        let plaintextData = Data(spanArray(plaintext))
        let nonceData = Data(spanArray(nonce))
        let aadData = Data(spanArray(aad))
        do {
            let sealed = try AES.GCM.seal(
                plaintextData,
                using: key,
                nonce: try AES.GCM.Nonce(data: nonceData),
                authenticating: aadData
            )
            return [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)
        } catch {
            throw .providerFailure
        }
    }

    public func open(
        _ ciphertext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        let combined = spanArray(ciphertext)
        guard combined.count >= Self.tagLength else {
            throw .invalidLength(expected: Self.tagLength, actual: combined.count)
        }
        let nonceData = Data(spanArray(nonce))
        let aadData = Data(spanArray(aad))

        let splitIndex = combined.count - Self.tagLength
        let encryptedData = Data(combined[0..<splitIndex])
        let tag = Data(combined[splitIndex...])

        do {
            let sealed = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonceData),
                ciphertext: encryptedData,
                tag: tag
            )
            return [UInt8](try AES.GCM.open(sealed, using: key, authenticating: aadData))
        } catch {
            throw .authenticationFailure
        }
    }

    @inline(__always)
    private func spanArray(_ span: Span<UInt8>) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(span.count)
        for i in 0..<span.count { out.append(span[i]) }
        return out
    }
}
