/// The single unified host `CryptoProvider` for swift-tls.
///
/// swift-tls's Embedded-clean cores (`TLSCryptoCore`, `TLSHandshakeCore`,
/// `DTLSHandshakeCore`, `TLSRecordCore`, `DTLSRecordCore`) are generic over
/// `C: CryptoProvider`. The host adapter specialises them at `C = TLSProvider`.
///
/// This replaces the former duplicate aggregate `TLSFoundationProvider`: there is
/// now ONE provider type in swift-tls. Its primitives are swift-tls-local thin
/// wrappers over swift-crypto / CryptoKit (the `TLS*` types in
/// `TLSProviderPrimitives.swift`, `TLSEd25519.swift`, `TLSX25519.swift`,
/// `TLS{P256,P384}Agreement.swift`, and the DER ECDSA schemes below).
///
/// Provider-unification note: the Embedded-first design called for specialising at
/// `P2PCrypto.DefaultCryptoProvider` (the stack-wide shared provider). That is
/// blocked for swift-tls specifically: `P2PCrypto` pulls a vendored swift-crypto
/// floored at `.macOS(.v26)`, and that `Crypto` product cannot satisfy
/// swift-certificates (whose targets support `.macOS(.v12)`) — SPM rejects the
/// graph. So swift-tls keeps its own (low-floor) swift-crypto and its own single
/// provider. The DER-vs-raw ECDSA distinction below is also genuinely TLS-specific
/// (TLS 1.3 CertificateVerify requires DER) and would have had to be overridden on
/// top of the shared provider regardless.
///
/// The ECDSA P-256 / P-384 schemes use the **DER** signature encoding TLS 1.3
/// CertificateVerify requires (RFC 8446 §4.2.3) — distinct from the libp2p-identity
/// raw `r || s` convention. They are kept byte-identical to the legacy path.

import Foundation
import Crypto
import P2PCoreBytes
import P2PCoreCrypto

/// Aggregates swift-tls's crypto primitives behind `P2PCoreCrypto.CryptoProvider`.
public enum TLSProvider: CryptoProvider {
    public typealias AESGCM128  = TLSUnsupportedAEAD
    public typealias AESGCM256  = TLSUnsupportedAEAD
    public typealias ChaChaPoly = TLSUnsupportedAEAD

    public typealias SHA256 = TLSSHA256
    public typealias SHA384 = TLSSHA384

    public typealias HKDFSHA256 = TLSHKDFSHA256
    public typealias HKDFSHA384 = TLSHKDFSHA384

    public typealias HMACSHA1   = TLSHMACSHA1
    public typealias HMACSHA256 = TLSHMACSHA256
    public typealias HMACSHA384 = TLSHMACSHA384

    public typealias X25519        = TLSX25519
    public typealias P256Agreement = TLSP256Agreement
    public typealias P384Agreement = TLSP384Agreement

    public typealias Ed25519       = TLSEd25519
    public typealias P256Signature = TLSDERP256Signature
    public typealias P384Signature = TLSDERP384Signature

    public typealias Random           = TLSRandom
    public typealias Clock            = TLSClock
    public typealias HeaderProtection = TLSHeaderProtection

    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> TLSUnsupportedAEAD {
        throw .unsupportedParameter
    }
    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> TLSUnsupportedAEAD {
        throw .unsupportedParameter
    }
    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> TLSUnsupportedAEAD {
        throw .unsupportedParameter
    }

    public static let random = TLSRandom()
    public static let clock  = TLSClock()
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
                rawRepresentation: rawRepresentation.tlsPrimData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P256.Signing.PublicKey(
                x963Representation: rawRepresentation.tlsPrimData()))
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
            let signature = try signingKey.key.signature(for: message.tlsPrimData())
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
            let sig = try P256.Signing.ECDSASignature(derRepresentation: signature.tlsPrimData())
            return verifyingKey.key.isValidSignature(sig, for: message.tlsPrimData())
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
                rawRepresentation: rawRepresentation.tlsPrimData()))
        } catch {
            throw .invalidLength(expected: 48, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P384.Signing.PublicKey(
                x963Representation: rawRepresentation.tlsPrimData()))
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
            let signature = try signingKey.key.signature(for: message.tlsPrimData())
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
            let sig = try P384.Signing.ECDSASignature(derRepresentation: signature.tlsPrimData())
            return verifyingKey.key.isValidSignature(sig, for: message.tlsPrimData())
        } catch {
            return false
        }
    }
}
