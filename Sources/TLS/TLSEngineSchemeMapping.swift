/// Facade-to-engine enum mappings shared by BOTH the host strategy
/// (`TLSConfigurationBridge`) and the Embedded strategy (`TLSEngineEmbeddedStrategy`).
///
/// These map the facade's `[UInt8]`-currency configuration enums onto the
/// Embedded-clean wire enums (`TLSWireCore.SignatureScheme` /
/// `TLSWireCore.CertificateType`). They are Foundation-free so they compile in both
/// builds.

import TLSWireCore

extension TLSIdentity.KeyType {
    var engineScheme: SignatureScheme {
        switch self {
        case .ecdsaP256: return .ecdsa_secp256r1_sha256
        case .ecdsaP384: return .ecdsa_secp384r1_sha384
        case .ed25519:   return .ed25519
        }
    }
}

extension TLSCertificateTypes.CertificateType {
    var engineType: CertificateType {
        switch self {
        case .x509:         return .x509
        case .rawPublicKey: return .rawPublicKey
        }
    }
}
