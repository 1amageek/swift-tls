/// Tier-1 DTLS 1.2 client over UDP datagrams.
///
/// The non-generic facade fixed to the unified `TLSCryptoProvider`. It wraps the
/// cored, Embedded-clean `DTLSClientEngine<TLSCryptoProvider>` (in swift-ssl)
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
/// ECDHE, signature verification, CertificateVerify signing, and cookie handling
/// are injected by the single portable strategy owned by this facade.
import Synchronization
import TLSCryptoProvider
import SSLDTLS
import DTLSWireCore

public final class DTLSClient: Sendable {
    private let engine: FacadeLock<DTLSClientEngineStorage>

    /// Creates a DTLS client with the given configuration.
    public init(configuration: DTLSConfiguration) throws(TLSError) {
        let engineConfig = try configuration.makeDTLSEngineConfiguration()
        let created: DTLSClientEngine<TLSCryptoProvider>
        do {
            created = try DTLSClientEngine<TLSCryptoProvider>(configuration: engineConfig)
        } catch {
            throw TLSError.fromDTLSEngine(error)
        }
        self.engine = FacadeLock(DTLSClientEngineStorage(value: created))
    }

    /// Starts the handshake, returning the ClientHello datagram(s) to send.
    public func startHandshake() throws(TLSError) -> [[UInt8]] {
        try run { (e) throws(DTLSEngineError) in try e.startHandshake() }
    }

    /// Feeds a received UDP datagram and returns the aggregate effects.
    public func receive(_ datagram: Span<UInt8>) throws(TLSError) -> DTLSOutput {
        let input = datagram.facadeArray()
        let result: Result<DTLSOutput, TLSError> = engine.withLock { storage in
            Result { () throws(DTLSEngineError) -> DTLSOutput in
                let output = try storage.value.receiveOwned(input)
                return DTLSOutput(from: consume output)
            }
            .mapError(TLSError.fromDTLSEngine)
        }
        switch result {
        case .success(let output): return output
        case .failure(let error): throw error
        }
    }

    /// Encrypts application data and returns the DTLS datagram to send.
    public func send(_ application: Span<UInt8>) throws(TLSError) -> [UInt8] {
        let input = application.facadeArray()
        return try run { (e) throws(DTLSEngineError) in
            try e.sendOwned(input)
        }
    }

    /// Emits a close_notify alert datagram to gracefully terminate.
    public func close() throws(TLSError) -> [UInt8] {
        try run { (e) throws(DTLSEngineError) in try e.close() }
    }

    /// Current timer token for the active handshake flight.
    public var retransmissionState: DTLSRetransmissionState {
        DTLSRetransmissionState(engine: engine.withLock { $0.value.retransmissionState })
    }

    /// Handles one timeout if `generation` still owns the active flight timer.
    public func handleTimeout(
        generation: UInt64
    ) throws(TLSError) -> DTLSTimeoutResult {
        let result = try run { (e) throws(DTLSEngineError) in
            try e.handleTimeout(generation: generation)
        }
        return DTLSTimeoutResult(engine: result)
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.withLock { $0.value.isEstablished } }

    /// Whether the connection has been closed.
    public var isClosed: Bool { engine.withLock { $0.value.isClosed } }

    /// Peer's presented DER-encoded certificate, if received.
    ///
    /// This value can become available before Finished authenticates the complete
    /// handshake. Treat it as peer-supplied bytes until ``isEstablished`` is true;
    /// callers that bind an out-of-band fingerprint must do so only afterwards.
    public var remoteCertificateDER: [UInt8]? {
        engine.withLock { $0.value.remoteCertificateDER }
    }

    /// The SRTP profile authenticated by the completed DTLS handshake.
    /// Returns `nil` until Finished has been verified.
    public var negotiatedSRTPProtectionProfile: DTLSSRTPProtectionProfile? {
        engine.withLock { engine in
            engine.value.negotiatedSRTPProfile.map(DTLSSRTPProtectionProfile.init(wireProfile:))
        }
    }

    /// Derives direction-safe SRTP master keying material via RFC 5705/5764.
    public func srtpKeyingMaterial() throws(TLSError) -> DTLSSRTPKeyingMaterial {
        try run { (engine) throws(DTLSEngineError) in
            guard let profile = engine.negotiatedSRTPProfile else {
                throw .protocolFailure(reason: "DTLS did not negotiate SRTP")
            }
            let bytes = try engine.exportKeyingMaterial(
                label: "EXTRACTOR-dtls_srtp",
                context: nil,
                length: 60
            )
            guard let material = DTLSSRTPKeyingMaterial.split(
                bytes,
                wireProtectionProfile: profile,
                localIsClient: true
            ) else {
                throw .internalError(reason: "Invalid DTLS-SRTP exporter output")
            }
            return material
        }
    }

    /// Runs an engine operation under the lock, mapping the engine error to the
    /// single facade `TLSError`. The facade is the caller that locks. The engine
    /// only throws `DTLSEngineError`, so the closure is typed-throws (Embedded-clean).
    private func run<R: Sendable>(
        _ body: (inout DTLSClientEngine<TLSCryptoProvider>) throws(DTLSEngineError) -> R
    ) throws(TLSError) -> R {
        let result: Result<R, TLSError> = engine.withLock { engine in
            Result { () throws(DTLSEngineError) -> R in try body(&engine.value) }
                .mapError(TLSError.fromDTLSEngine)
        }
        switch result {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

/// A concrete facade-owned layout for the provider-specialized engine.
///
/// Normal Swift 6.4 WASM must not ask `Mutex<Value>` to dynamically materialize
/// the value witness table for a cross-module generic engine specialization. This
/// one-field concrete owner gives the lock a statically emitted layout while the
/// protected state and mutation entry point remain identical on every target.
private struct DTLSClientEngineStorage: Sendable {
    var value: DTLSClientEngine<TLSCryptoProvider>
}
