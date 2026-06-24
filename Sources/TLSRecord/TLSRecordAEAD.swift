/// Host (non-Embedded) concrete `AEAD` seam conformance for TLS record protection.
///
/// The Embedded-clean `TLSRecordCore.TLSRecordProtector<C, A>` is generic over
/// `A: P2PCoreCrypto.AEAD`. The host adapter specialises it with this
/// swift-crypto–backed AEAD, which is byte-identical to the AEAD behavior
/// swift-tls shipped before the seam refactor (the legacy `TLSRecordCryptor`'s
/// `AES.GCM.seal/open` and `ChaChaPoly.seal/open`).
///
/// `TLSCryptoProvider`'s own AEAD associated types are the unsupported
/// placeholders (the key schedule performs no AEAD), so record protection brings
/// its own concrete AEAD rather than reusing `C.makeAESGCM*`. A single concrete
/// type dispatches on the cipher suite internally so one `A` parameter covers all
/// three TLS 1.3 suites.
///
/// AEAD-open failure throws ``P2PCoreCrypto/CryptoError/authenticationFailure``
/// (the protector then collapses it to `badRecordMac`) — no silent fallback.

import Foundation
import Crypto
import TLSCore
import TLSWireCore
import P2PCoreBytes
import P2PCoreCrypto

/// A swift-crypto–backed AEAD bound to one key, selecting the algorithm from the
/// negotiated TLS 1.3 cipher suite.
public struct TLSRecordAEAD: P2PCoreCrypto.AEAD {
    public static let nonceLength = 12
    public static let tagLength   = 16

    private let key: SymmetricKey
    private let cipherSuite: CipherSuite

    /// Builds the AEAD from raw key bytes for `cipherSuite`.
    public init(key: [UInt8], cipherSuite: CipherSuite) {
        self.key = SymmetricKey(data: Data(key))
        self.cipherSuite = cipherSuite
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
            switch cipherSuite {
            case .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384:
                let sealed = try AES.GCM.seal(
                    plaintextData,
                    using: key,
                    nonce: try AES.GCM.Nonce(data: nonceData),
                    authenticating: aadData
                )
                return [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)
            case .tls_chacha20_poly1305_sha256:
                let sealed = try ChaChaPoly.seal(
                    plaintextData,
                    using: key,
                    nonce: try ChaChaPoly.Nonce(data: nonceData),
                    authenticating: aadData
                )
                return [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)
            }
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
            switch cipherSuite {
            case .tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384:
                let sealed = try AES.GCM.SealedBox(
                    nonce: try AES.GCM.Nonce(data: nonceData),
                    ciphertext: encryptedData,
                    tag: tag
                )
                return [UInt8](try AES.GCM.open(sealed, using: key, authenticating: aadData))
            case .tls_chacha20_poly1305_sha256:
                let sealed = try ChaChaPoly.SealedBox(
                    nonce: try ChaChaPoly.Nonce(data: nonceData),
                    ciphertext: encryptedData,
                    tag: tag
                )
                return [UInt8](try ChaChaPoly.open(sealed, using: key, authenticating: aadData))
            }
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
