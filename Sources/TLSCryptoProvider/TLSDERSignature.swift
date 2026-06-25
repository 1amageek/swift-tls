/// DER-encoded ECDSA signature schemes for the TLS 1.3 CertificateVerify wire
/// (RFC 8446 §4.2.3).
///
/// These are the ONLY swift-tls-local crypto primitive types remaining after the
/// provider unification (embedded-first-api.md §2.2): every other primitive is
/// supplied by the shared ``P2PCrypto/DefaultCryptoProvider``. ECDSA is the one
/// exception — the shared provider emits raw `r||s` ECDSA signatures (the
/// libp2p-identity convention), whereas TLS 1.3 CertificateVerify requires DER.
/// ``TLSCryptoProvider`` overrides `P256Signature`/`P384Signature` with these.
///
/// They are kept byte-identical to the legacy path: a signing failure throws
/// ``P2PCoreCrypto/CryptoError/providerFailure``; an invalid signature is an
/// explicit `false` from `isValid` (no silent fallback).
///
/// Host-only (`#if !hasFeature(Embedded)`): swift-crypto's `derRepresentation`
/// supplies the DER encoding. The Embedded build uses ``EmbeddedDERP256Signature``
/// / ``EmbeddedDERP384Signature`` (BoringSSL raw `r || s` + a `P2PCoreDER` DER
/// wrapper that is byte-identical to this path).

#if !hasFeature(Embedded)
import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto

// MARK: - Span -> Data (one bulk copy)

extension Span where Element == UInt8 {
    @inline(__always)
    func tlsDERSignatureData() -> Data {
        let n = count
        guard n > 0 else { return Data() }
        return withUnsafeBufferPointer { source in
            Data(buffer: source)
        }
    }
}

// MARK: - DER ECDSA P-256 (TLS CertificateVerify wire format)

/// ECDSA over P-256 with **DER** signatures, as TLS 1.3 CertificateVerify requires
/// (RFC 8446 §4.2.3). Distinct from the raw `r || s` libp2p-identity convention.
///
/// - Signing key raw representation = 32-byte raw scalar.
/// - Verifying key raw representation = 65-byte X9.62 uncompressed point.
/// - Signatures are `derRepresentation`. A signing failure throws
///   ``P2PCoreCrypto/CryptoError/providerFailure``; an invalid signature is an
///   explicit `false` from `isValid` (no silent fallback).
public enum TLSDERP256Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable {
        let key: P256.Signing.PrivateKey
    }

    public struct VerifyingKey: Sendable {
        let key: P256.Signing.PublicKey
    }

    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        SigningKey(key: P256.Signing.PrivateKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        do {
            return SigningKey(key: try P256.Signing.PrivateKey(
                rawRepresentation: rawRepresentation.tlsDERSignatureData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P256.Signing.PublicKey(
                x963Representation: rawRepresentation.tlsDERSignatureData()))
        } catch {
            throw .invalidLength(expected: 65, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(key: signingKey.key.publicKey)
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        [UInt8](signingKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        [UInt8](verifyingKey.key.x963Representation)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            let signature = try signingKey.key.signature(for: message.tlsDERSignatureData())
            return [UInt8](signature.derRepresentation)
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        do {
            let sig = try P256.Signing.ECDSASignature(derRepresentation: signature.tlsDERSignatureData())
            return verifyingKey.key.isValidSignature(sig, for: message.tlsDERSignatureData())
        } catch {
            return false
        }
    }
}

// MARK: - DER ECDSA P-384 (TLS CertificateVerify wire format)

/// ECDSA over P-384 with **DER** signatures for TLS 1.3 CertificateVerify
/// (RFC 8446 §4.2.3). See ``TLSDERP256Signature`` for the DER-vs-raw rationale.
public enum TLSDERP384Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable {
        let key: P384.Signing.PrivateKey
    }

    public struct VerifyingKey: Sendable {
        let key: P384.Signing.PublicKey
    }

    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        SigningKey(key: P384.Signing.PrivateKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        do {
            return SigningKey(key: try P384.Signing.PrivateKey(
                rawRepresentation: rawRepresentation.tlsDERSignatureData()))
        } catch {
            throw .invalidLength(expected: 48, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P384.Signing.PublicKey(
                x963Representation: rawRepresentation.tlsDERSignatureData()))
        } catch {
            throw .invalidLength(expected: 97, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(key: signingKey.key.publicKey)
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        [UInt8](signingKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        [UInt8](verifyingKey.key.x963Representation)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            let signature = try signingKey.key.signature(for: message.tlsDERSignatureData())
            return [UInt8](signature.derRepresentation)
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        do {
            let sig = try P384.Signing.ECDSASignature(derRepresentation: signature.tlsDERSignatureData())
            return verifyingKey.key.isValidSignature(sig, for: message.tlsDERSignatureData())
        } catch {
            return false
        }
    }
}

#endif // !hasFeature(Embedded)
