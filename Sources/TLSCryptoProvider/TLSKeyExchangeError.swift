/// Typed failures for provider-owned (EC)DHE adaptation.

import P2PCoreCrypto

public enum TLSKeyExchangeCoreError: Error, Equatable, Sendable {
    case unsupportedGroup
    case invalidPublicKeyLength(expected: Int, actual: Int)
    case crypto(CryptoError)
}
