/// Tier-1 DTLS 1.2 server over UDP datagrams.
///
/// Mirror of `DTLSClient`, wrapping the cored, Embedded-clean
/// `DTLSServerEngine<TLSCryptoProvider>` (in swift-ssl) under a `Mutex`. The
/// server receives `remoteAddress` for the HelloVerifyRequest cookie binding
/// (RFC 6347 §4.2.1); the facade threads it through `receive(_:from:)`.
///
/// ECDHE, the ServerKeyExchange signing, client CertificateVerify verification,
/// and HelloVerifyRequest cookie HMAC are injected by the single portable
/// strategy owned by this facade.
import Synchronization
import TLSCryptoProvider
import SSLDTLS
import DTLSWireCore

public final class DTLSServer: Sendable {
    private let engine: FacadeLock<DTLSServerEngineStorage>

    /// Creates a DTLS server with the given configuration.
    public init(configuration: DTLSConfiguration) throws(TLSError) {
        let engineConfig = try configuration.makeDTLSEngineConfiguration()
        let created: DTLSServerEngine<TLSCryptoProvider>
        do {
            created = try DTLSServerEngine<TLSCryptoProvider>(configuration: engineConfig)
        } catch {
            throw TLSError.fromDTLSEngine(error)
        }
        self.engine = FacadeLock(DTLSServerEngineStorage(value: created))
    }

    /// Starts the handshake. A server has nothing to send until the first
    /// ClientHello arrives; the return is empty.
    public func startHandshake() throws(TLSError) -> [[UInt8]] {
        try run { (e) throws(DTLSEngineError) in try e.startHandshake() }
    }

    /// Feeds a received UDP datagram. `remoteAddress` binds the
    /// HelloVerifyRequest cookie to the client's transport address.
    public func receive(_ datagram: Span<UInt8>, from remoteAddress: Span<UInt8>) throws(TLSError) -> DTLSOutput {
        do {
            return try engine.withLock { storage in
                let output = try storage.value.receive(datagram, from: remoteAddress)
                return DTLSOutput(from: consume output)
            }
        } catch {
            throw TLSError.fromDTLSEngine(error)
        }
    }

    /// Encrypts application data and returns the DTLS datagram to send.
    public func send(_ application: Span<UInt8>) throws(TLSError) -> [UInt8] {
        return try run { (e) throws(DTLSEngineError) in
            try e.send(application)
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
            guard engine.isEstablished else {
                throw .handshakeNotComplete
            }
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
                localIsClient: false
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
        _ body: (inout DTLSServerEngine<TLSCryptoProvider>) throws(DTLSEngineError) -> R
    ) throws(TLSError) -> R {
        do {
            return try engine.withLock { engine in
                try body(&engine.value)
            }
        } catch {
            throw TLSError.fromDTLSEngine(error)
        }
    }
}

/// A concrete facade-owned layout for the provider-specialized engine.
///
/// Normal Swift 6.4 WASM must not ask `Mutex<Value>` to dynamically materialize
/// the value witness table for a cross-module generic engine specialization. This
/// one-field concrete owner gives the lock a statically emitted layout while the
/// protected state and mutation entry point remain identical on every target.
private struct DTLSServerEngineStorage: Sendable {
    var value: DTLSServerEngine<TLSCryptoProvider>
}
