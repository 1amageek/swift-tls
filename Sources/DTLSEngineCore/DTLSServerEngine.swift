/// The Embedded-clean, sans-IO DTLS 1.2 SERVER connection engine.
///
/// `DTLSServerEngine<C>` is the cored replacement for the host
/// `DTLSConnection`+`DTLSServerHandshakeHandler` orchestration. Value type,
/// caller-locked, sans-IO — the mirror of ``DTLSClientEngine``. The server takes the
/// client's transport address through `receive(_:from:)` for the HelloVerifyRequest
/// cookie binding (RFC 6347 §4.2.1).
///
/// ```
///   receive(ClientHello, from: addr)
///                 ─► DTLSServerHandshake<C>.ingestClientHello
///                 ─► .needCookie → mint cookie (injected HMAC) → HelloVerifyRequest
///                 ─► .verifyCookie → verify cookie (injected HMAC, fail-closed)
///                                  → select suite + sign ServerKeyExchange (injected)
///                                  → acceptCookieAndBuildFlight → server flight
///   receive(Cert / CKE / CertVerify / Finished)
///                 ─► drive ingest* (ECDHE agree, client CertificateVerify verify,
///                    Finished MAC + client-cert policy in-core, fail-closed)
/// ```
///
/// The handshake FSM core owns the transcript + key schedule + Finished MAC +
/// message_seq ordering + the cookie fail-closed rule + the
/// `requireClientCertificate` policy. The engine owns the record layer + flights +
/// reassembly + cipher-suite selection. ECDHE / signing / verification / cookie
/// HMAC are INJECTED (see ``DTLSEngineConfiguration``); X.509 never enters here.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`, no
/// swift-crypto, no X509; typed throws (`DTLSEngineError`); bare `catch { switch }`.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import DTLSWireCore
import DTLSHandshakeCore
import DTLSRecordCore

public struct DTLSServerEngine<C: CryptoProvider>: Sendable {

    let configuration: DTLSEngineConfiguration<C>

    // MARK: - Handshake FSM (the core)

    var fsm: DTLSServerHandshake<C>

    /// Our ECDHE private-key handle (set when building the server flight).
    var keyExchangeHandle: [UInt8]?
    var keyExchangeGroup: NamedGroup?

    // MARK: - Record layer + flight + reassembly (driver-owned)

    var record: DTLSRecordEngine<C>
    var flights: DTLSFlightController
    var reassembly: HandshakeReassemblyBuffer

    var pendingKeyBlock: DTLSKeyBlockCore?
    var negotiatedCipherSuite: DTLSCipherSuite?

    // MARK: - Connection lifecycle

    enum Phase: Sendable, Equatable {
        case start
        case handshaking
        case connected
        case closed
        case failed
    }
    var phase: Phase

    /// The peer (client) certificate DER, surfaced after the Certificate message.
    public internal(set) var remoteCertificateDER: [UInt8]?

    /// The validated peer identifier (e.g. libp2p PeerID) from `validateCertificate`.
    var validatedPeerIdentifier: [UInt8]?

    var isProcessing: Bool

    static var maxBufferSize: Int { 256 * 1024 }

    // MARK: - Initialization

    public init(configuration: DTLSEngineConfiguration<C>) throws(DTLSEngineError) {
        // A server requires identity + all crypto seams incl. the cookie HMAC.
        guard configuration.ecdheGenerate != nil, configuration.ecdheAgree != nil,
              configuration.sign != nil, configuration.signingScheme != nil,
              configuration.verifyPeerSignature != nil, configuration.randomBytes != nil,
              configuration.makeCookie != nil, configuration.verifyCookie != nil else {
            throw .invalidConfiguration(reason: "DTLS server requires identity + crypto seams (ecdhe/sign/verify/random/cookie)")
        }
        guard !configuration.certificateChainDER.isEmpty else {
            throw .invalidConfiguration(reason: "DTLS server requires a certificate")
        }
        self.configuration = configuration
        self.fsm = DTLSServerHandshake<C>(requireClientCertificate: configuration.requireClientCertificate)
        self.keyExchangeHandle = nil
        self.keyExchangeGroup = nil
        self.record = DTLSRecordEngine<C>()
        self.flights = DTLSFlightController()
        self.reassembly = HandshakeReassemblyBuffer()
        self.pendingKeyBlock = nil
        self.negotiatedCipherSuite = nil
        self.phase = .start
        self.remoteCertificateDER = nil
        self.validatedPeerIdentifier = nil
        self.isProcessing = false
    }

    // MARK: - Accessors

    public var isEstablished: Bool { phase == .connected }
    public var isClosed: Bool { phase == .closed }
    public var peerIdentifier: [UInt8]? { validatedPeerIdentifier }

    // MARK: - startHandshake

    /// A server has nothing to send until the first ClientHello arrives.
    public mutating func startHandshake() throws(DTLSEngineError) -> [[UInt8]] {
        guard phase == .start else { throw .handshakeAlreadyStarted }
        phase = .handshaking
        return []
    }

    // MARK: - send / close / handleTimeout

    public mutating func send(_ application: Span<UInt8>) throws(DTLSEngineError) -> [UInt8] {
        guard phase != .closed else { throw .connectionClosed }
        guard phase != .failed else { throw .protocolFailure(reason: "connection in failed state") }
        guard phase == .connected else { throw .handshakeNotComplete }
        return try record.encodeRecord(contentType: .applicationData, plaintext: application.facadeArrayLocal())
    }

    public mutating func close() throws(DTLSEngineError) -> [UInt8] {
        guard phase != .closed else { return [] }
        phase = .closed
        let alertBytes: [UInt8] = [1, 0] // close_notify (warning, 0)
        return try record.encodeRecord(contentType: .alert, plaintext: alertBytes)
    }

    public mutating func handleTimeout() throws(DTLSEngineError) -> [[UInt8]] {
        guard phase != .closed, phase != .failed else { return [] }
        return try flights.retransmit()
    }

    // MARK: - Cipher-suite selection (mirrors the host adapter)

    func selectCipherSuite(from offered: [DTLSCipherSuite]) -> DTLSCipherSuite? {
        for suite in configuration.supportedCipherSuites where offered.contains(suite) {
            return suite
        }
        return nil
    }
}
