/// TLS 1.3 Key Schedule (RFC 8446 Section 7.1) — Foundation adapter.
///
/// The full key-schedule logic now lives in the Embedded-clean
/// `TLSCryptoCore.TLSKeySchedule<C>`, routed through the
/// `P2PCoreCrypto.CryptoProvider` seam. This adapter type preserves the existing
/// `SymmetricKey`/`Data` public API by specialising the core at
/// `C = TLSProvider` (swift-tls's own swift-crypto backend) and
/// bridging `[UInt8]` ↔ `SymmetricKey`/`Data` at the boundary. Behavior is
/// byte-for-byte identical to the pre-seam implementation; see
/// `RFC8448VectorTests` and `TLSKeyScheduleSeamDifferentialTests`.
///
/// ```
///             0
///             |
///   PSK ->  HKDF-Extract = Early Secret
///             |
///       Derive-Secret(., "derived", "")
///             |
///  (EC)DHE -> HKDF-Extract = Handshake Secret
///             |
///       Derive-Secret(., "derived", "")
///             |
///     0 -> HKDF-Extract = Master Secret
/// ```

import Foundation
import Crypto
import TLSWireCore
import TLSCryptoCore

// MARK: - Bridge helpers

@inline(__always)
private func symmetricKeyBytes(_ key: SymmetricKey) -> [UInt8] {
    key.withUnsafeBytes { [UInt8]($0) }
}

@inline(__always)
private func symmetricKey(_ bytes: [UInt8]) -> SymmetricKey {
    SymmetricKey(data: Data(bytes))
}

/// Maps an out-of-order/state error from the core onto the adapter error.
/// HKDF-Expand length overflow is impossible for the fixed TLS 1.3 output
/// lengths (≤ 48 bytes), so a `.crypto` failure here indicates a programmer
/// error rather than a recoverable condition; it surfaces loudly (no silent
/// fallback).
@inline(__always)
private func mapCoreError(_ error: TLSKeyScheduleCoreError) -> TLSKeyScheduleError {
    switch error {
    case .invalidState:
        return .invalidState("Key schedule used out of order")
    case .crypto(let cryptoError):
        return .keyDerivationFailed("HKDF failure: \(cryptoError)")
    }
}

// MARK: - TLS Key Schedule

/// Manages TLS 1.3 key derivation (Foundation adapter over `TLSCryptoCore`).
public struct TLSKeySchedule: Sendable {

    private var core: TLSCryptoCore.TLSKeySchedule<TLSProvider>

    /// The negotiated cipher suite.
    public var cipherSuite: CipherSuite { core.cipherSuite }

    /// Hash length (32 for SHA-256, 48 for SHA-384).
    public var hashLength: Int { core.hashLength }

    // MARK: - Initialization

    /// Creates a new key schedule
    /// - Parameter cipherSuite: The negotiated cipher suite
    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        self.core = TLSCryptoCore.TLSKeySchedule<TLSProvider>(cipherSuite: cipherSuite)
    }

    /// The underlying Embedded-clean core value.
    ///
    /// Used by the handshake state machine to hand the key schedule (already
    /// advanced to the handshake-secret state) to
    /// `TLSHandshakeCore.TLSClientAuthMachine`, and to restore it afterwards so
    /// the adapter can derive ticket PSKs post-handshake.
    var coreValue: TLSCryptoCore.TLSKeySchedule<TLSProvider> {
        get { core }
        set { core = newValue }
    }

    // MARK: - Early Secret

    /// Derive early secret from PSK (or use 0 for non-PSK mode)
    /// - Parameter psk: Pre-shared key, or nil for non-PSK mode
    public mutating func deriveEarlySecret(psk: SymmetricKey? = nil) {
        core.deriveEarlySecret(psk: psk.map { symmetricKeyBytes($0) })
    }

    // MARK: - Handshake Secret

    /// Derive handshake secrets from (EC)DHE shared secret
    /// - Returns: (client_handshake_traffic_secret, server_handshake_traffic_secret)
    public mutating func deriveHandshakeSecrets(
        sharedSecret: KeyExchangeSecret,
        transcriptHash: Data
    ) throws -> (client: SymmetricKey, server: SymmetricKey) {
        do {
            let (client, server) = try core.deriveHandshakeSecrets(
                sharedSecret: [UInt8](sharedSecret.rawRepresentation),
                transcriptHash: [UInt8](transcriptHash)
            )
            return (client: symmetricKey(client), server: symmetricKey(server))
        } catch {
            throw mapCoreError(error)
        }
    }

    // MARK: - Application Secret

    /// Derive application (1-RTT) secrets
    /// - Returns: (client_application_traffic_secret_0, server_application_traffic_secret_0)
    public mutating func deriveApplicationSecrets(
        transcriptHash: Data
    ) throws -> (client: SymmetricKey, server: SymmetricKey) {
        do {
            let (client, server) = try core.deriveApplicationSecrets(
                transcriptHash: [UInt8](transcriptHash)
            )
            return (client: symmetricKey(client), server: symmetricKey(server))
        } catch {
            throw mapCoreError(error)
        }
    }

    // MARK: - Key Update

    /// Next application traffic secret (for key update)
    public func nextApplicationSecret(
        from currentSecret: SymmetricKey
    ) -> SymmetricKey {
        do {
            return symmetricKey(try core.nextApplicationSecret(from: symmetricKeyBytes(currentSecret)))
        } catch {
            preconditionFailure("HKDF-Expand-Label for traffic-update cannot overflow: \(error)")
        }
    }

    // MARK: - Finished Key

    /// The finished key derived from a base key
    public func finishedKey(from baseKey: SymmetricKey) -> SymmetricKey {
        do {
            return symmetricKey(try core.finishedKey(from: symmetricKeyBytes(baseKey)))
        } catch {
            preconditionFailure("HKDF-Expand-Label for finished key cannot overflow: \(error)")
        }
    }

    /// The finished verify_data
    public func finishedVerifyData(
        forKey key: SymmetricKey,
        transcriptHash: Data
    ) -> Data {
        Data(core.finishedVerifyData(
            forKey: symmetricKeyBytes(key),
            transcriptHash: [UInt8](transcriptHash)
        ))
    }

    // MARK: - Exporter Master Secret

    /// Derive the exporter master secret
    public func deriveExporterMasterSecret(transcriptHash: Data) throws -> SymmetricKey {
        do {
            return symmetricKey(try core.deriveExporterMasterSecret(transcriptHash: [UInt8](transcriptHash)))
        } catch {
            throw mapCoreError(error)
        }
    }

    // MARK: - Resumption Master Secret

    /// Derive the resumption master secret
    public func deriveResumptionMasterSecret(transcriptHash: Data) throws -> SymmetricKey {
        do {
            return symmetricKey(try core.deriveResumptionMasterSecret(transcriptHash: [UInt8](transcriptHash)))
        } catch {
            throw mapCoreError(error)
        }
    }

    /// Derive a resumption PSK from the resumption master secret and ticket nonce
    public func deriveResumptionPSK(
        resumptionMasterSecret: SymmetricKey,
        ticketNonce: Data
    ) -> SymmetricKey {
        do {
            return symmetricKey(try core.deriveResumptionPSK(
                resumptionMasterSecret: symmetricKeyBytes(resumptionMasterSecret),
                ticketNonce: [UInt8](ticketNonce)
            ))
        } catch {
            preconditionFailure("HKDF-Expand-Label for resumption PSK cannot overflow: \(error)")
        }
    }

    // MARK: - PSK/Early Secrets

    /// Derive the binder key from the early secret
    public func deriveBinderKey(isResumption: Bool) throws -> SymmetricKey {
        do {
            return symmetricKey(try core.deriveBinderKey(isResumption: isResumption))
        } catch {
            throw mapCoreError(error)
        }
    }

    /// Derive the client early traffic secret (for 0-RTT)
    public func deriveClientEarlyTrafficSecret(transcriptHash: Data) throws -> SymmetricKey {
        do {
            return symmetricKey(try core.deriveClientEarlyTrafficSecret(transcriptHash: [UInt8](transcriptHash)))
        } catch {
            throw mapCoreError(error)
        }
    }

    /// Derive the early exporter master secret
    public func deriveEarlyExporterMasterSecret(transcriptHash: Data) throws -> SymmetricKey {
        do {
            return symmetricKey(try core.deriveEarlyExporterMasterSecret(transcriptHash: [UInt8](transcriptHash)))
        } catch {
            throw mapCoreError(error)
        }
    }

    /// The current early secret (for PSK-related computations)
    public func currentEarlySecret() throws -> SymmetricKey {
        do {
            return symmetricKey(try core.currentEarlySecret())
        } catch {
            throw mapCoreError(error)
        }
    }

    // MARK: - Exporter Keying Material

    /// Export keying material (RFC 8446 Section 7.5)
    public func exportKeyingMaterial(
        exporterMasterSecret: SymmetricKey,
        label: String,
        context: Data?,
        length: Int
    ) -> Data {
        do {
            return Data(try core.exportKeyingMaterial(
                exporterMasterSecret: symmetricKeyBytes(exporterMasterSecret),
                label: label,
                context: context.map { [UInt8]($0) },
                length: length
            ))
        } catch {
            preconditionFailure("HKDF-Expand-Label for exported keying material failed: \(error)")
        }
    }
}

// MARK: - Errors

/// Errors from TLS key schedule operations
public enum TLSKeyScheduleError: Error, Sendable {
    case invalidState(String)
    case keyDerivationFailed(String)
}

// MARK: - Traffic Keys

/// Traffic keys derived from a traffic secret
public struct TrafficKeys: Sendable {
    /// The encryption key
    public let key: SymmetricKey

    /// The IV (12 bytes for TLS 1.3, kept as Data for XOR with sequence number)
    public let iv: Data

    /// Derives traffic keys from a traffic secret
    /// - Parameters:
    ///   - secret: The traffic secret
    ///   - cipherSuite: The negotiated cipher suite (determines key length and hash)
    public init(
        secret: SymmetricKey,
        cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256
    ) {
        let secretBytes = secret.withUnsafeBytes { [UInt8]($0) }
        do {
            let keys = try TLSTrafficKeys.derive(
                secret: secretBytes.span,
                cipherSuite: cipherSuite,
                provider: TLSProvider.self
            )
            self.key = SymmetricKey(data: Data(keys.key))
            self.iv = Data(keys.iv)
        } catch {
            preconditionFailure("HKDF-Expand-Label for traffic keys cannot overflow: \(error)")
        }
    }
}
