/// Tier-1 DTLS 1.2 client over UDP datagrams.
///
/// The non-generic facade fixed to the unified `TLSCryptoProvider`. It wraps the
/// cored, Embedded-clean `DTLSClientEngine<TLSCryptoProvider>` (in `DTLSEngineCore`)
/// and presents a `[UInt8]`/`Span<UInt8>` surface with a single `TLSError`. The
/// datagram methods return `[[UInt8]]` (a list of datagrams to send), matching
/// DTLS's record-per-datagram model.
///
/// ## The engine pattern (driver model)
///
/// The engine is a **value-type, sans-IO, `mutating` state machine** that drives
/// the cored DTLS handshake FSM through a value-type record layer (epoch + 48-bit
/// seq + anti-replay + AEAD) and a caller-driven flight controller. The facade is
/// the **caller that locks**: it is a `final class` holding the engine in a `Mutex`
/// (the engine itself holds no lock), so the public methods are `Sendable`-safe.
///
/// ECDHE, the ServerKeyExchange-signature verification, and the CertificateVerify
/// signing are INJECTED into the engine via the host strategy bridge
/// (`DTLSCertificate.makeDTLSEngineConfiguration`, gated `#if !hasFeature(Embedded)`);
/// X.509 never enters the engine itself.

#if !hasFeature(Embedded)
import Foundation
import TLSCore
import DTLSCore
#endif
import Synchronization
import TLSCryptoProvider
import DTLSEngineCore

public final class DTLSClient: Sendable {
    private let engine: FacadeLock<DTLSClientEngine<TLSCryptoProvider>>

    /// Creates a DTLS client with the given configuration.
    public init(configuration: DTLSConfiguration) throws(TLSError) {
        let engineConfig = try configuration.makeDTLSEngineConfiguration()
        let created: DTLSClientEngine<TLSCryptoProvider>
        do {
            created = try DTLSClientEngine<TLSCryptoProvider>(configuration: engineConfig)
        } catch {
            throw TLSError.fromDTLSEngine(error)
        }
        self.engine = FacadeLock(created)
    }

    /// Starts the handshake, returning the ClientHello datagram(s) to send.
    public func startHandshake() throws(TLSError) -> [[UInt8]] {
        try run { (e) throws(DTLSEngineError) in try e.startHandshake() }
    }

    /// Feeds a received UDP datagram and returns the aggregate effects.
    public func receive(_ datagram: Span<UInt8>) throws(TLSError) -> DTLSOutput {
        let input = datagram.facadeArray()
        let output = try run { (e) throws(DTLSEngineError) in try e.receive(input.span) }
        return DTLSOutput(from: output)
    }

    /// Encrypts application data and returns the DTLS datagram to send.
    public func send(_ application: Span<UInt8>) throws(TLSError) -> [UInt8] {
        let input = application.facadeArray()
        return try run { (e) throws(DTLSEngineError) in try e.send(input.span) }
    }

    /// Emits a close_notify alert datagram to gracefully terminate.
    public func close() throws(TLSError) -> [UInt8] {
        try run { (e) throws(DTLSEngineError) in try e.close() }
    }

    /// Datagrams to retransmit on a timeout (DTLS flight retransmission).
    public func handleTimeout() throws(TLSError) -> [[UInt8]] {
        try run { (e) throws(DTLSEngineError) in try e.handleTimeout() }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.withLock { $0.isEstablished } }

    /// Whether the connection has been closed.
    public var isClosed: Bool { engine.withLock { $0.isClosed } }

    /// Peer's DER-encoded certificate, if presented. `nil` if the handshake is
    /// incomplete or no certificate was received. X.509 chain validation is the
    /// caller's responsibility; this is the raw leaf the engine recorded.
    public var remoteCertificateDER: [UInt8]? {
        engine.withLock { $0.remoteCertificateDER }
    }

    #if !hasFeature(Embedded)
    /// Peer's SHA-256 certificate fingerprint in RFC 8122 / SDP textual form
    /// (e.g. `"sha-256 AB:CD:..."`), used for WebRTC DTLS-SRTP peer
    /// authentication. `nil` if no peer certificate is available. Host-only: the
    /// SDP fingerprint formatting lives in the swift-crypto-backed `DTLSCore`.
    public var remoteFingerprint: String? {
        guard let der = remoteCertificateDER else { return nil }
        return CertificateFingerprint.fromDER(Data(der)).sdpFormat
    }
    #endif

    /// Runs an engine operation under the lock, mapping the engine error to the
    /// single facade `TLSError`. The facade is the caller that locks. The engine
    /// only throws `DTLSEngineError`, so the closure is typed-throws (Embedded-clean).
    private func run<R: Sendable>(
        _ body: (inout DTLSClientEngine<TLSCryptoProvider>) throws(DTLSEngineError) -> R
    ) throws(TLSError) -> R {
        let result: Result<R, TLSError> = engine.withLock { engine in
            Result { () throws(DTLSEngineError) -> R in try body(&engine) }
                .mapError(TLSError.fromDTLSEngine)
        }
        switch result {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}
