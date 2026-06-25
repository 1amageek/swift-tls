/// Tier-1 TLS 1.3 server over a reliable byte stream (TCP).
///
/// Mirror of `TLSClient`, fixed to the unified `TLSCryptoProvider`, wrapping the
/// cored `TLSServerEngine<TLSCryptoProvider>` (in `TLSEngineCore`). A server
/// requires identity material (signing key + certificate chain) in its
/// configuration. The facade is a `final class` that holds the value-type engine in
/// a `Mutex` (the caller that locks); X.509 trust + signing are injected via the
/// host strategy.

import Synchronization
import TLSCryptoProvider
import TLSEngineCore
#if !hasFeature(Embedded)
import TLSCore
#endif

public final class TLSServer: Sendable {
    private let engine: FacadeLock<TLSServerEngine<TLSCryptoProvider>>

    /// Creates a TLS server. The configuration must carry identity material.
    public init(configuration: TLSConfiguration) throws(TLSError) {
        let engineConfig = try configuration.makeServerEngineConfiguration()
        let created: TLSServerEngine<TLSCryptoProvider>
        do {
            created = try TLSServerEngine<TLSCryptoProvider>(configuration: engineConfig)
        } catch {
            throw TLSError.fromEngine(error)
        }
        self.engine = FacadeLock(created)
    }

    /// Starts the handshake. For a server this returns no bytes until the client's
    /// ClientHello arrives; the return is empty.
    public func startHandshake() async throws(TLSError) -> [UInt8] {
        try run { (e) throws(TLSEngineError) in try e.startHandshake() }
    }

    /// Feeds bytes received from the peer and returns the aggregate effects.
    public func receive(_ bytes: Span<UInt8>) async throws(TLSError) -> TLSOutput {
        let input = bytes.facadeArray()
        let output = try run { (e) throws(TLSEngineError) in try e.receive(input.span) }
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
        return try run { (e) throws(TLSEngineError) in try e.send(input.span) }
    }

    /// Emits a close_notify alert (encoded record) to gracefully terminate.
    public func close() async throws(TLSError) -> [UInt8] {
        try run { (e) throws(TLSEngineError) in try e.close() }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.withLock { $0.isEstablished } }

    /// The negotiated ALPN protocol, if any.
    public var negotiatedALPN: String? { engine.withLock { $0.negotiatedALPN } }

    /// Peer's DER-encoded certificates (leaf first), if presented. Populated after
    /// the handshake. X.509 chain validation is the injected validator's job
    /// (`TLSConfiguration.certificateValidator`); this is the raw chain the engine
    /// recorded. `nil` if the peer presented no certificate.
    public var peerCertificates: [[UInt8]]? {
        engine.withLock { $0.peerCertificates }
    }

    /// The application peer identity established by the certificate validator, if
    /// any. Reconstructed from the validator's identifier bytes and the recorded
    /// peer certificate chain. `nil` when no validator ran or it produced no
    /// identity (an anonymous handshake stays `nil`); a validator throw fails the
    /// handshake, so this never surfaces an unverified peer.
    public var peerIdentity: PeerIdentity? {
        engine.withLock { engine in
            guard let identifier = engine.peerIdentifier else { return nil }
            let certificates = (engine.peerCertificates ?? []).map { Certificate(der: $0) }
            return PeerIdentity(identifier: identifier, certificates: certificates)
        }
    }

    private func run<R: Sendable>(
        _ body: (inout TLSServerEngine<TLSCryptoProvider>) throws(TLSEngineError) -> R
    ) throws(TLSError) -> R {
        let result: Result<R, TLSError> = engine.withLock { engine in
            Result { () throws(TLSEngineError) -> R in try body(&engine) }
                .mapError(TLSError.fromEngine)
        }
        switch result {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}
