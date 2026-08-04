import SSLTLS
import Synchronization

/// TLS 1.3 client session over a reliable byte stream.
///
/// The session owns the canonical `swift-ssl` handshake state. `Mutex` is the
/// sole isolation boundary; no I/O or suspension occurs while it is held.
public final class TLSClient: Sendable {
    private let engine: Mutex<TLSClientStorage>
    private let capture: CanonicalPeerCapture

    public init(configuration: TLSConfiguration = .init()) throws(TLSError) {
        let factory = try configuration.makeClientFactory()
        let handshake = consume factory.handshake
        self.engine = Mutex(TLSClientStorage(handshake: handshake))
        self.capture = factory.capture
    }

    public func startHandshake() async throws(TLSError) -> [UInt8] {
        let output = try run { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.start()
        }
        return try CanonicalTLSProjection.bytesToSend(output)
    }

    public func receive(_ bytes: Span<UInt8>) async throws(TLSError) -> TLSOutput {
        let output = try run { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.receive(bytes)
        }
        return try CanonicalTLSProjection.output(output)
    }

    public func send(_ application: Span<UInt8>) async throws(TLSError) -> [UInt8] {
        let output = try run { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.sendApplicationData(application)
        }
        return try CanonicalTLSProjection.bytesToSend(output)
    }

    public func close() async throws(TLSError) -> [UInt8] {
        let output = try run { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            let output = try state.handshake.sendCloseNotify()
            state.closed = true
            return output
        }
        return try CanonicalTLSProjection.bytesToSend(output)
    }

    public var isEstablished: Bool {
        engine.withLock { $0.handshake.isEstablished && !$0.closed }
    }

    public var negotiatedALPN: String? {
        engine.withLock { state -> String? in
            guard let protocolValue = state.handshake.negotiatedApplicationProtocol else {
                return nil
            }
            return protocolValue.withIdentifierBytes { CanonicalTLSConversion.string(from: $0) }
        }
    }

    public var peerCertificates: [[UInt8]]? {
        capture.certificates?.map { $0.der }
    }

    public var peerIdentity: PeerIdentity? {
        capture.identity
    }

    private func run<Result: Sendable>(
        _ operation: (inout TLSClientStorage) throws(TLS13HandshakeEngineError) -> Result
    ) throws(TLSError) -> Result {
        do {
            return try engine.withLock { state in
                try operation(&state)
            }
        } catch let error as TLS13HandshakeEngineError {
            throw error.facadeError
        } catch {
#if hasFeature(Embedded)
            throw .internalError(reason: "TLS engine failure")
#else
            throw .internalError(reason: String(describing: error))
#endif
        }
    }
}

private struct TLSClientStorage: ~Copyable, Sendable {
    var handshake: TLS13ClientHandshake
    var closed = false

    init(handshake: consuming TLS13ClientHandshake) {
        self.handshake = handshake
    }
}
