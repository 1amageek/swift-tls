import SSLTLS
import Synchronization

/// TLS 1.3 server session over a reliable byte stream.
public final class TLSServer: Sendable {
    private let engine: Mutex<TLSServerStorage>
    private let capture: CanonicalPeerCapture

    public init(configuration: TLSConfiguration) throws(TLSError) {
        let factory = try configuration.makeServerFactory()
        let handshake = consume factory.handshake
        self.engine = Mutex(TLSServerStorage(handshake: handshake))
        self.capture = factory.capture
    }

    /// A server waits for the peer's ClientHello and therefore emits no bytes initially.
    public func startHandshake() async throws(TLSError) -> [UInt8] {
        []
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
        _ operation: (inout TLSServerStorage) throws(TLS13HandshakeEngineError) -> Result
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

private struct TLSServerStorage: ~Copyable, Sendable {
    var handshake: TLS13ServerHandshake
    var closed = false

    init(handshake: consuming TLS13ServerHandshake) {
        self.handshake = handshake
    }
}
