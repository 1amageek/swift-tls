/// Output actions emitted by the Embedded-clean TLS 1.3 handshake FSM.
///
/// The sans-IO FSM core never performs I/O: each `mutating` transition returns
/// the side effects it wants the adapter to carry out — handshake bytes to send
/// at an encryption level, traffic secrets that became available, and lifecycle
/// signals — as a flat list of these value-type actions. The `TLSCore` adapter
/// translates them into its Foundation `TLSOutput` stream (bridging `[UInt8]`
/// secrets to `SymmetricKey`, `[UInt8]` messages to `Data`).
///
/// Ordering is significant and preserved verbatim: the adapter emits the actions
/// in the order the core returns them so the wire flight and key-availability
/// sequence stay byte-identical to the pre-FSM implementation.
///
/// Embedded-clean: no Foundation, no `any`, no Mutex, value types only.

import TLSWireCore

/// The encryption level at which a flight of handshake bytes must be sent.
///
/// Mirrors ``TLSWireCore/TLSEncryptionLevel`` (re-exported for the adapter's
/// convenience) so the core needs no Foundation level type.
public typealias TLSHandshakeLevel = TLSEncryptionLevel

/// A traffic-secret pair that became available at a given level.
///
/// `client` / `server` are raw secret bytes (`[UInt8]`); a `nil` direction means
/// "no key for this direction" (e.g. the server never sends 0-RTT). The adapter
/// wraps each non-nil secret in a `SymmetricKey`.
public struct TLSHandshakeSecrets: Sendable, Equatable {
    public let level: TLSHandshakeLevel
    public let client: [UInt8]?
    public let server: [UInt8]?
    public let cipherSuite: CipherSuite

    public init(
        level: TLSHandshakeLevel,
        client: [UInt8]?,
        server: [UInt8]?,
        cipherSuite: CipherSuite
    ) {
        self.level = level
        self.client = client
        self.server = server
        self.cipherSuite = cipherSuite
    }
}

/// A single side effect the adapter must carry out.
public enum TLSHandshakeAction: Sendable, Equatable {
    /// Send these complete handshake message bytes (header included) at `level`.
    case send(bytes: [UInt8], level: TLSHandshakeLevel)

    /// New traffic secrets are available.
    case secretsAvailable(TLSHandshakeSecrets)

    /// The 0-RTT early-data phase has ended (discard the early-data cryptor).
    case earlyDataEnd

    /// The adapter must run its (Foundation/closure) certificate validator on the
    /// raw peer certificates now — after the CertificateVerify signature has been
    /// verified and folded into the transcript, and before the server Finished is
    /// processed. The adapter MUST propagate any validator error and must NOT
    /// continue the handshake if it throws.
    case runCertificateValidator

    /// The handshake is complete; `alpn` is the negotiated protocol (if any),
    /// `zeroRTTAccepted` reflects whether the server accepted 0-RTT.
    case handshakeComplete(alpn: String?, zeroRTTAccepted: Bool)
}
