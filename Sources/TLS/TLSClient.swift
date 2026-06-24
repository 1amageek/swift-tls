/// Tier-1 TLS 1.3 client over a reliable byte stream (TCP).
///
/// The non-generic facade fixed to the unified `TLSCryptoProvider`. It wraps the
/// cored, Embedded-clean `TLSClientEngine<TLSCryptoProvider>` (in `TLSEngineCore`)
/// and presents a `[UInt8]`/`Span<UInt8>` surface with a single `TLSError`.
///
/// ## The engine pattern (driver model)
///
/// The engine is a **value-type, sans-IO, `mutating` state machine** that drives
/// the cored handshake FSMs through a record-layer suite-protector. The facade is
/// the **caller that locks**: it is a `final class` holding the engine in a `Mutex`
/// (the engine itself holds no lock), so the public methods are `Sendable`-safe.
/// They are `async` for source compatibility (the engine never actually suspends —
/// it is lock-based, not I/O-bound — so they complete promptly).
///
/// X.509 trust + CertificateVerify signing are INJECTED into the engine via the
/// host strategy bridge (`TLSCore.makeClientEngineConfiguration`, gated
/// `#if canImport(Foundation)`); X.509 never enters the engine itself.
///
/// Usage:
/// 1. `startHandshake()` → send the returned bytes to the peer.
/// 2. Feed peer bytes into `receive(_:)`; send `output.bytesToSend`; read
///    `output.applicationData`; check `output.handshakeComplete`.
/// 3. After the handshake, `send(_:)` encrypts application data.
/// 4. `close()` emits a close_notify.

import Synchronization
import TLSCore
import TLSEngineCore

public final class TLSClient: Sendable {
    private let engine: Mutex<TLSClientEngine<TLSCryptoProvider>>

    /// Creates a TLS client with the given configuration.
    public init(configuration: TLSConfiguration = .init()) throws(TLSError) {
        let engineConfig = try configuration.makeClientEngineConfiguration()
        let created: TLSClientEngine<TLSCryptoProvider>
        do {
            created = try TLSClientEngine<TLSCryptoProvider>(configuration: engineConfig)
        } catch {
            throw TLSError.fromEngine(error)
        }
        self.engine = Mutex(created)
    }

    /// Starts the handshake, returning the ClientHello bytes to send.
    public func startHandshake() async throws(TLSError) -> [UInt8] {
        try run { try $0.startHandshake() }
    }

    /// Feeds bytes received from the peer and returns the aggregate effects.
    public func receive(_ bytes: Span<UInt8>) async throws(TLSError) -> TLSOutput {
        let input = bytes.facadeArray()
        let output = try run { try $0.receive(input.span) }
        return TLSOutput(
            bytesToSend: output.bytesToSend,
            applicationData: output.applicationData,
            handshakeComplete: output.handshakeComplete,
            peerClosed: output.peerClosed
        )
    }

    /// Encrypts application data and returns the TLS records to send.
    public func send(_ application: Span<UInt8>) async throws(TLSError) -> [UInt8] {
        let input = application.facadeArray()
        return try run { try $0.send(input.span) }
    }

    /// Emits a close_notify alert (encoded record) to gracefully terminate.
    public func close() async throws(TLSError) -> [UInt8] {
        try run { try $0.close() }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.withLock { $0.isEstablished } }

    /// The negotiated ALPN protocol, if any.
    public var negotiatedALPN: String? { engine.withLock { $0.negotiatedALPN } }

    /// The application peer identity returned by the certificate validator, if any.
    public var peerIdentity: PeerIdentity? { nil }

    /// Runs an engine operation under the lock, mapping any engine error to the
    /// single facade `TLSError`. The facade is the caller that locks. The closure
    /// is untyped-throws (Swift cannot infer a typed-throws closure literal here);
    /// the engine only throws `TLSEngineError`, which `TLSError.from` maps.
    private func run<R: Sendable>(
        _ body: (inout TLSClientEngine<TLSCryptoProvider>) throws -> R
    ) throws(TLSError) -> R {
        // Map the (non-Sendable) thrown error to the Sendable facade `TLSError`
        // INSIDE the lock so only Sendable values cross the lock boundary.
        let result: Result<R, TLSError> = engine.withLock { engine in
            do {
                return .success(try body(&engine))
            } catch {
                return .failure(TLSError.from(error))
            }
        }
        switch result {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}
