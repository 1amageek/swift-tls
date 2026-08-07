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
            recordOverhead: 24,
            seal: { @Sendable (
                plaintext: Span<UInt8>,
                explicitNonce: [UInt8],
                aad: [UInt8],
                output: inout MutableSpan<UInt8>
            ) throws(DTLSRecordProtectionError) in
                try seal(
                    protector,
                    plaintext: plaintext,
                    explicitNonce: explicitNonce,
                    aad: aad,
                    into: &output
                )
            },
            open: { @Sendable (
                ciphertext: Span<UInt8>,
                aad: [UInt8],
                output: inout MutableSpan<UInt8>
            ) throws(DTLSRecordProtectionError) in
                try open(
                    protector,
                    ciphertext: ciphertext,
                    aad: aad,
                    into: &output
                )
            }
        )
    }

    package static func makeDTLSAES256RecordProtectionContext(
        key: [UInt8],
        fixedIV: [UInt8]
    ) throws(DTLSRecordProtectionError) -> DTLSRecordProtectionContext {
        let protector = try makeSSLDTLSProtector(key: key, fixedIV: fixedIV)
        return DTLSRecordProtectionContext(
            recordOverhead: 24,
            seal: { @Sendable (
                plaintext: Span<UInt8>,
                explicitNonce: [UInt8],
                aad: [UInt8],
                output: inout MutableSpan<UInt8>
            ) throws(DTLSRecordProtectionError) in
                try seal(
                    protector,
                    plaintext: plaintext,
                    explicitNonce: explicitNonce,
                    aad: aad,
                    into: &output
                )
            },
            open: { @Sendable (
                ciphertext: Span<UInt8>,
                aad: [UInt8],
                output: inout MutableSpan<UInt8>
            ) throws(DTLSRecordProtectionError) in
                try open(
                    protector,
                    ciphertext: ciphertext,
                    aad: aad,
                    into: &output
                )
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
        do {
            return try DTLS12AESGCMRecordProtector(
                key: key.span,
                fixedIV: fixedIV.span,
                epoch: 0
            )
        } catch {
            throw mapSealError(error)
        }
    }

    private static func seal(
        _ protector: DTLS12AESGCMRecordProtector,
        plaintext: Span<UInt8>,
        explicitNonce: [UInt8],
        aad: [UInt8],
        into output: inout MutableSpan<UInt8>
    ) throws(DTLSRecordProtectionError) {
        do {
            try protector.sealRaw(
                plaintext: plaintext,
                explicitNonce: explicitNonce.span,
                authenticatedData: aad.span,
                into: &output
            )
        } catch {
            throw mapSealError(error)
        }
    }

    private static func open(
        _ protector: DTLS12AESGCMRecordProtector,
        ciphertext: Span<UInt8>,
        aad: [UInt8],
        into output: inout MutableSpan<UInt8>
    ) throws(DTLSRecordProtectionError) {
        do {
            try protector.openRaw(
                recordFragment: ciphertext,
                authenticatedData: aad.span,
                into: &output
            )
        } catch {
            throw mapOpenError(error)
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
