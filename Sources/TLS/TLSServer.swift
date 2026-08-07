import SSLCore
import SSLTLS
import Synchronization

/// TLS 1.3 server session over a reliable byte stream.
public final class TLSServer: Sendable {
    private let engine: Mutex<TLSServerStorage>
    private let capture: CanonicalPeerCapture

    public init(
        configuration: TLSConfiguration,
        resumptionState: TLSResumptionState? = nil
    ) throws(TLSError) {
        let factory = try configuration.makeServerFactory(
            resumptionState: resumptionState
        )
        let handshake = consume factory.handshake
        let localCredentialProvider = consume factory.localCredentialProvider
        let peerTrustProvider = factory.peerTrustProvider
        self.engine = Mutex(
            TLSServerStorage(
                handshake: handshake,
                verificationInstant: factory.verificationInstant,
                localCredentialProvider: consume localCredentialProvider,
                peerTrustProvider: peerTrustProvider,
                peerCertificateValidator: factory.peerCertificateValidator,
                certificateValidator: factory.certificateValidator
            )
        )
        self.capture = factory.capture
    }

    /// A server waits for the peer's ClientHello and therefore emits no bytes initially.
    public func startHandshake() throws(TLSError) -> [UInt8] {
        guard !engine.withLock({ $0.closed }) else {
            throw .connectionClosed
        }
        return []
    }

    /// Feeds exactly one complete TLS record. The transport adapter owns record
    /// framing and must split coalesced records before calling this method.
    /// External trust, credential, and signing callbacks run outside the
    /// session mutex and may suspend independently of the TLS state machine.
    public func receive(_ bytes: Span<UInt8>) throws(TLSError) -> TLSOutput {
        guard !engine.withLock({ $0.closed }) else {
            throw .connectionClosed
        }
        let established = engine.withLock { $0.handshake.isEstablished }
        if !established {
            return try receiveHandshakeRecord(bytes)
        }
        return try receiveApplicationRecord(bytes)
    }

    /// Processes one complete TLS record and preserves a capability suspension.
    public func receiveStep(_ bytes: Span<UInt8>) throws(TLSError) -> TLSOutput {
        return try runTransition { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.receiveRecordStep(bytes)
        }
    }

    /// Resumes the exact suspended TLS transition identified by `response.token`.
    public func resume(_ response: TLSCapabilityResponse) throws(TLSError) -> TLSOutput {
        guard !engine.withLock({ $0.closed }) else {
            throw .connectionClosed
        }
        let verificationInstant = engine.withLock { $0.verificationInstant }
        let coreResponse = try response.core(
            verificationInstant: verificationInstant
        )
        return try runTransition { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.resume(coreResponse)
        }
    }

    public func send(_ application: Span<UInt8>) throws(TLSError) -> [UInt8] {
        try requireEstablished()
        let output = try run { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.sendApplicationData(application)
        }
        return try CanonicalTLSProjection.bytesToSend(output)
    }

    /// Creates one TLS 1.3 NewSessionTicket for this established connection.
    ///
    /// The returned wire bytes are sent to the peer, while the paired
    /// ``TLSResumptionState`` is retained by the server and consumed by the
    /// next ``TLSServer`` instance that accepts that ticket.
    public func sendNewSessionTicket(
        lifetime: UInt32,
        ageAdd: UInt32,
        ticketNonce: Span<UInt8>,
        ticket: Span<UInt8>,
        maximumEarlyDataByteCount: UInt32 = 0,
        extensions: Span<UInt8> = Span<UInt8>()
    ) throws(TLSError) -> TLSIssuedSessionTicket {
        try requireEstablished()
        let result: Result<TLSIssuedSessionTicket, TLSError> = engine.withLock {
            state in
            do {
                let issued = try state.handshake.sendNewSessionTicket(
                    lifetime: lifetime,
                    ageAdd: ageAdd,
                    ticketNonce: ticketNonce,
                    ticket: ticket,
                    issuedAt: state.verificationInstant,
                    maximumEarlyDataByteCount: maximumEarlyDataByteCount,
                    extensions: extensions
                )
                let bytes = try CanonicalTLSProjection.bytesToSend(issued.output)
                let resumptionState = TLSResumptionState(
                    core: issued.takeResumptionState()
                )
                return .success(
                    TLSIssuedSessionTicket(
                        bytesToSend: bytes,
                        resumptionState: resumptionState
                    )
                )
            } catch let error as TLS13HandshakeEngineError {
                return .failure(error.facadeError)
            } catch let error as TLSError {
                return .failure(error)
            } catch {
#if hasFeature(Embedded)
                return .failure(.internalError(reason: "TLS engine failure"))
#else
                return .failure(.internalError(reason: String(describing: error)))
#endif
            }
        }
        return try result.get()
    }

    /// Requests a TLS 1.3 application traffic key update.
    ///
    /// The returned bytes must be written to the peer before subsequent
    /// application data. If `requestPeerUpdate` is true, the peer is asked to
    /// update its sending key as well; its response is handled by `receive(_:)`.
    public func requestKeyUpdate(
        requestPeerUpdate: Bool = false
    ) throws(TLSError) -> [UInt8] {
        try requireEstablished()
        let output = try run { state throws(TLS13HandshakeEngineError) in
            guard !state.closed else { throw .invalidState }
            return try state.handshake.requestKeyUpdate(
                requestPeerUpdate: requestPeerUpdate
            )
        }
        return try CanonicalTLSProjection.bytesToSend(output)
    }

    public func close() throws(TLSError) -> [UInt8] {
        try requireEstablished()
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
        guard engine.withLock({ $0.handshake.isEstablished }) else { return nil }
        return capture.certificates?.map { $0.der }
    }

    public var peerIdentity: PeerIdentity? {
        guard engine.withLock({ $0.handshake.isEstablished }) else { return nil }
        return capture.identity
    }

    private func requireEstablished() throws(TLSError) {
        let status = engine.withLock { state in
            (closed: state.closed, established: state.handshake.isEstablished)
        }
        if status.closed {
            throw .connectionClosed
        }
        guard status.established else {
            throw .handshakeNotComplete
        }
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

    private func runTransition(
        _ operation: (inout TLSServerStorage) throws(TLS13HandshakeEngineError)
            -> TLS13StreamHandshakeTransition
    ) throws(TLSError) -> TLSOutput {
        do {
            var transition = try engine.withLock { state in
                guard !state.closed else { throw TLS13HandshakeEngineError.invalidState }
                return try operation(&state)
            }
            while true {
                switch consume transition {
                case .output(let output):
                    return try CanonicalTLSProjection.output(output)
                case .suspended(let request, let output):
                    let facadeRequest = TLSCapabilityRequest(core: request)
                    guard let response = try resolveCapability(facadeRequest) else {
                        let suspended = TLS13StreamHandshakeTransition.suspended(
                            request,
                            output
                        )
                        return try CanonicalTLSProjection.transition(consume suspended)
                    }
                    let verificationInstant = engine.withLock { $0.verificationInstant }
                    let coreResponse = try response.core(
                        verificationInstant: verificationInstant
                    )
                    transition = try engine.withLock { state in
                        guard !state.closed else {
                            throw TLS13HandshakeEngineError.invalidState
                        }
                        return try state.handshake.resume(coreResponse)
                    }
                }
            }
        } catch let error as TLS13HandshakeEngineError {
            throw error.facadeError
        } catch let error as TLSError {
            throw error
        } catch {
#if hasFeature(Embedded)
            throw .internalError(reason: "TLS engine failure")
#else
            throw .internalError(reason: String(describing: error))
#endif
        }
    }

    private func receiveHandshakeRecord(
        _ bytes: Span<UInt8>
    ) throws(TLSError) -> TLSOutput {
        try runTransition { state throws(TLS13HandshakeEngineError) in
            try state.handshake.receiveRecordStep(bytes)
        }
    }

    private func receiveApplicationRecord(
        _ bytes: Span<UInt8>
    ) throws(TLSError) -> TLSOutput {
        do {
            let result = try engine.withLock { state -> TLS13StreamRecordTransition in
                if state.closed { throw TLS13HandshakeEngineError.invalidState }
                return try state.handshake.receiveApplicationRecordStep(bytes)
            }
            switch consume result {
            case .applicationData(let applicationData):
                return TLSOutput(
                    applicationData: CanonicalTLSProjection.array(from: applicationData)
                )
            case .postHandshake(let transition):
                return try resolvePostHandshake(consume transition)
            case .sessionTicket:
                throw TLSError.protocolFailure(
                    reason: "server received an unexpected NewSessionTicket"
                )
            case .alert(let alert):
                return try engine.withLock { state in
                    try handlePeerAlert(alert, state: &state)
                }
            }
        } catch let error as TLSError {
            throw error
        } catch let error as TLS13HandshakeEngineError {
            engine.withLock { $0.closed = true }
            throw error.facadeError
        } catch {
#if hasFeature(Embedded)
            throw .internalError(reason: "TLS engine failure")
#else
            throw .internalError(reason: String(describing: error))
#endif
        }
    }

    private func resolvePostHandshake(
        _ initial: consuming TLS13StreamHandshakeTransition
    ) throws(TLSError) -> TLSOutput {
        do {
            var transition = consume initial
            while true {
                switch consume transition {
                case .output(let output):
                    return try CanonicalTLSProjection.output(output)
                case .suspended(let request, let output):
                    let facadeRequest = TLSCapabilityRequest(core: request)
                    guard let response = try resolveCapability(facadeRequest) else {
                        let suspended = TLS13StreamHandshakeTransition.suspended(
                            request,
                            output
                        )
                        return try CanonicalTLSProjection.transition(consume suspended)
                    }
                    let verificationInstant = engine.withLock { $0.verificationInstant }
                    let coreResponse = try response.core(
                        verificationInstant: verificationInstant
                    )
                    transition = try engine.withLock { state in
                        try state.handshake.resume(coreResponse)
                    }
                }
            }
        } catch let error as TLSError {
            throw error
        } catch let error as TLS13HandshakeEngineError {
            engine.withLock { $0.closed = true }
            throw error.facadeError
        } catch {
#if hasFeature(Embedded)
            throw .internalError(reason: "TLS engine failure")
#else
            throw .internalError(reason: String(describing: error))
#endif
        }
    }

    private func resolveCapability(
        _ request: TLSCapabilityRequest
    ) throws(TLSError) -> TLSCapabilityResponse? {
        switch request {
        case .peerTrustEvaluation(let trustRequest):
            let policy = engine.withLock { state in
                (
                    pathValidator: state.peerCertificateValidator,
                    callback: state.certificateValidator,
                    provider: state.peerTrustProvider
                )
            }
            if let pathValidator = policy.pathValidator {
                do {
                    _ = try pathValidator.validate(
                        trustRequest.coreRequest.certificateMessage,
                        at: trustRequest.verificationInstant
                    )
                } catch {
                    return .peerTrustRejected(trustRequest.token)
                }
            }
            if let callback = policy.callback {
                let identity = try callback(trustRequest.certificates)
                capture.record(trustRequest.certificates, identity: identity)
            }
            return policy.provider?.response(for: request)
                ?? .peerTrustAccepted(trustRequest.token)
        case .credentialSelection, .signature:
            let result: Result<TLSCapabilityResponse?, TLSError> = engine.withLock { state in
                do {
                    return .success(
                        try state.localCredentialProvider?.response(for: request)
                    )
                } catch let error as TLSError {
                    return .failure(error)
                } catch {
                    return .failure(.internalError(reason: "local capability failed"))
                }
            }
            return try result.get()
        }
    }

    private func handlePeerAlert(
        _ alert: TLSAlert,
        state: inout TLSServerStorage
    ) throws(TLSError) -> TLSOutput {
        state.closed = true
        if alert == .closeNotify {
            return TLSOutput(peerClosed: true)
        }
        throw .fatalAlert(code: alert.rawValue, reason: "peer sent a TLS alert")
    }
}

private struct TLSServerStorage: ~Copyable, Sendable {
    var handshake: TLS13ServerHandshake
    let verificationInstant: VerificationInstant
    let localCredentialProvider: CanonicalTLSLocalCredentialProvider?
    let peerTrustProvider: CanonicalTLSPeerTrustProvider?
    let peerCertificateValidator: (any TLS13ClientCertificateValidating)?
    let certificateValidator:
        (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?
    var closed = false

    init(
        handshake: consuming TLS13ServerHandshake,
        verificationInstant: VerificationInstant,
        localCredentialProvider: consuming CanonicalTLSLocalCredentialProvider?,
        peerTrustProvider: CanonicalTLSPeerTrustProvider?,
        peerCertificateValidator: (any TLS13ClientCertificateValidating)?,
        certificateValidator:
            (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?
    ) {
        self.handshake = handshake
        self.verificationInstant = verificationInstant
        self.localCredentialProvider = consume localCredentialProvider
        self.peerTrustProvider = peerTrustProvider
        self.peerCertificateValidator = peerCertificateValidator
        self.certificateValidator = certificateValidator
    }
}
