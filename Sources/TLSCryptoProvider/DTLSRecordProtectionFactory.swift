import DTLSRecordCore
import P2PCoreBytes
import P2PCoreCrypto
import SSLCore
import SSLDTLS

extension TLSCryptoProvider {
    package static func makeDTLSAES128RecordProtectionContext(
        key: [UInt8],
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) -> DTLSRecordProtectionContext {
        let protector = try makeSSLDTLSProtector(key: key, fixedIV: fixedIV)
        return DTLSRecordProtectionContext(
            seal: { @Sendable (
                plaintext: [UInt8],
                explicitNonce: [UInt8],
                aad: [UInt8]
            ) throws(DTLSRecordProtectionError) -> [UInt8] in
                try seal(protector, plaintext: plaintext, explicitNonce: explicitNonce, aad: aad)
            },
            open: { @Sendable (
                ciphertext: [UInt8],
                aad: [UInt8]
            ) throws(DTLSRecordProtectionError) -> [UInt8] in
                try open(protector, ciphertext: ciphertext, aad: aad)
            }
        )
    }

    package static func makeDTLSAES256RecordProtectionContext(
        key: [UInt8],
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) -> DTLSRecordProtectionContext {
        let protector = try makeSSLDTLSProtector(key: key, fixedIV: fixedIV)
        return DTLSRecordProtectionContext(
            seal: { @Sendable (
                plaintext: [UInt8],
                explicitNonce: [UInt8],
                aad: [UInt8]
            ) throws(DTLSRecordProtectionError) -> [UInt8] in
                try seal(protector, plaintext: plaintext, explicitNonce: explicitNonce, aad: aad)
            },
            open: { @Sendable (
                ciphertext: [UInt8],
                aad: [UInt8]
            ) throws(DTLSRecordProtectionError) -> [UInt8] in
                try open(protector, ciphertext: ciphertext, aad: aad)
            }
        )
    }

    private static func makeSSLDTLSProtector(
        key: [UInt8],
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) -> DTLS12AESGCMRecordProtector {
        guard fixedIV.count == DTLS12AESGCMRecordProtector.fixedIVByteCount else {
            throw .invalidFixedIVLength(
                expected: DTLS12AESGCMRecordProtector.fixedIVByteCount,
                actual: fixedIV.count
            )
        }
        guard key.count == 16 || key.count == 32 else {
            throw .crypto(.invalidLength(expected: 16, actual: key.count))
        }
        // The validated lengths are within SecretByteCount's limit. Any
        // allocation failure is an invariant failure, never a fallback.
        return try! DTLS12AESGCMRecordProtector(
            key: key.span,
            fixedIV: fixedIV.span,
            epoch: 0
        )
    }

    private static func seal(
        _ protector: DTLS12AESGCMRecordProtector,
        plaintext: [UInt8],
        explicitNonce: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        do {
            let bytes = try protector.sealRaw(
                plaintext: plaintext.span,
                explicitNonce: explicitNonce.span,
                authenticatedData: aad.span
            )
            return copy(bytes)
        } catch {
            throw mapSealError(error)
        }
    }

    private static func open(
        _ protector: DTLS12AESGCMRecordProtector,
        ciphertext: [UInt8],
        aad: [UInt8]
    ) throws(DTLSRecordProtectionError) -> [UInt8] {
        do {
            let bytes = try protector.openRaw(
                recordFragment: ciphertext.span,
                authenticatedData: aad.span
            )
            return copy(bytes)
        } catch {
            throw mapOpenError(error)
        }
    }

    private static func copy(_ bytes: OwnedBytes) -> [UInt8] {
        bytes.withBorrowedBytes { source in
            var result: [UInt8] = []
            result.reserveCapacity(source.count)
            var index = 0
            while index < source.count {
                result.append(source[index])
                index += 1
            }
            return result
        }
    }

    private static func mapSealError(_ error: DTLS12RecordError) -> DTLSRecordProtectionError {
        switch error {
        case .invalidExplicitNonceLength(let actual):
            return .invalidExplicitNonceLength(expected: 8, actual: actual)
        case .aead:
            return .crypto(.providerFailure)
        case .invalidKeyLength(let actual):
            return .crypto(.invalidLength(expected: 16, actual: actual))
        case .invalidFixedIVLength(let actual):
            return .invalidFixedIVLength(expected: 4, actual: actual)
        default:
            return .crypto(.providerFailure)
        }
    }

    private static func mapOpenError(_ error: DTLS12RecordError) -> DTLSRecordProtectionError {
        switch error {
        case .ciphertextTooShort(let actual):
            return .ciphertextTooShort(minimum: 24, actual: actual)
        case .invalidExplicitNonceLength(let actual):
            return .invalidExplicitNonceLength(expected: 8, actual: actual)
        case .aead:
            return .decryptionFailed
        default:
            return .decryptionFailed
        }
    }
}
