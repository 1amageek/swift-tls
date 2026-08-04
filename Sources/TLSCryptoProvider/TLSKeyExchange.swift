/// Provider-owned (EC)DHE adapter for the DTLS/TLS session facade.
///
/// Protocol state machines do not own key serialization or concrete primitive
/// selection. This adapter maps the negotiated wire group to the injected
/// `CryptoProvider` capability and returns the wire representation plus an
/// opaque raw private-key handle to the caller-owned engine.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore

/// (EC)DHE key exchange parameterised by the concrete crypto provider.
public enum TLSKeyExchange<C: CryptoProvider> {

    /// The wire-format public-key length for `group`, or `nil` when the group
    /// is not supported by the provider's DH capability.
    public static func publicKeyLength(for group: NamedGroup) -> Int? {
        switch group {
        case .x25519: return 32
        case .secp256r1: return 65
        case .secp384r1: return 97
        case .secp521r1, .x448, .x25519MLKEM768: return nil
        }
    }

    /// Ephemeral key material already serialized in the negotiated wire format.
    public struct EphemeralKeyPair: Sendable {
        public let group: NamedGroup
        public let publicKeyBytes: [UInt8]
        public let privateKeyBytes: [UInt8]
    }

    /// Generates a key pair for a supported DH group.
    public static func generate(
        for group: NamedGroup
    ) throws(TLSKeyExchangeCoreError) -> EphemeralKeyPair {
        switch group {
        case .x25519:
            return try generate(group: group, agreement: C.X25519.self)
        case .secp256r1:
            return try generate(group: group, agreement: C.P256Agreement.self)
        case .secp384r1:
            return try generate(group: group, agreement: C.P384Agreement.self)
        case .secp521r1, .x448, .x25519MLKEM768:
            throw .unsupportedGroup
        }
    }

    private static func generate<A: KeyAgreement>(
        group: NamedGroup,
        agreement: A.Type
    ) throws(TLSKeyExchangeCoreError) -> EphemeralKeyPair {
        let privateKey: A.PrivateKey
        do {
            privateKey = try A.generatePrivateKey()
        } catch {
            throw .crypto(error)
        }
        let publicKey = A.publicKey(for: privateKey)
        return EphemeralKeyPair(
            group: group,
            publicKeyBytes: A.rawRepresentation(of: publicKey),
            privateKeyBytes: A.rawRepresentation(of: privateKey)
        )
    }

    /// Computes the raw shared secret from a provider-owned private handle and
    /// a peer's wire public key. The borrowed spans do not escape this call.
    public static func sharedSecret(
        group: NamedGroup,
        privateKeyBytes: Span<UInt8>,
        peerPublicKeyBytes: Span<UInt8>
    ) throws(TLSKeyExchangeCoreError) -> [UInt8] {
        switch group {
        case .x25519:
            return try sharedSecret(
                agreement: C.X25519.self,
                privateKeyBytes: privateKeyBytes,
                peerPublicKeyBytes: peerPublicKeyBytes,
                expectedPublicKeyLength: 32
            )
        case .secp256r1:
            return try sharedSecret(
                agreement: C.P256Agreement.self,
                privateKeyBytes: privateKeyBytes,
                peerPublicKeyBytes: peerPublicKeyBytes,
                expectedPublicKeyLength: 65
            )
        case .secp384r1:
            return try sharedSecret(
                agreement: C.P384Agreement.self,
                privateKeyBytes: privateKeyBytes,
                peerPublicKeyBytes: peerPublicKeyBytes,
                expectedPublicKeyLength: 97
            )
        case .secp521r1, .x448, .x25519MLKEM768:
            throw .unsupportedGroup
        }
    }

    private static func sharedSecret<A: KeyAgreement>(
        agreement: A.Type,
        privateKeyBytes: Span<UInt8>,
        peerPublicKeyBytes: Span<UInt8>,
        expectedPublicKeyLength: Int
    ) throws(TLSKeyExchangeCoreError) -> [UInt8] {
        guard peerPublicKeyBytes.count == expectedPublicKeyLength else {
            throw .invalidPublicKeyLength(
                expected: expectedPublicKeyLength,
                actual: peerPublicKeyBytes.count
            )
        }
        do {
            let privateKey = try A.privateKey(rawRepresentation: privateKeyBytes)
            let peerPublicKey = try A.publicKey(rawRepresentation: peerPublicKeyBytes)
            return try A.sharedSecret(privateKey: privateKey, peerPublicKey: peerPublicKey)
        } catch {
            throw .crypto(error)
        }
    }
}
