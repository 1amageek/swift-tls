/// The Embedded-clean, sans-IO TLS 1.3 CLIENT connection engine.
///
/// `TLSClientEngine<C>` is the cored replacement for the host
/// `TLSConnection`+`TLS13Handler`+`ClientStateMachine` orchestration on the core
/// handshake/record path. It is a **value type**, **caller-locked** (the facade
/// holds it under its own actor/lock; the engine itself takes `mutating` methods
/// and never reaches for a `Mutex`), and **sans-IO** (the caller does socket I/O):
///
/// ```
/// var e = try TLSClientEngine<C>(configuration: cfg)
/// let hello = try e.startHandshake()          // → ClientHello records to send
/// let out   = try e.receive(peerBytes.span)   // → bytes to send / app data / done
/// let recs  = try e.send(appData.span)         // → encrypted app records
/// let bye   = try e.close()                    // → close_notify record
/// ```
///
/// ## What it drives (the ENGINE PATTERN)
///
/// ```
///   receive(Span) ─► TLSRecordCodec.decode  (one record at a time)
///                 ─► resolveRecord           (decrypt via recv protector if encrypted)
///                 ─► reassemble handshake messages (HandshakeCodec)
///                 ─► dispatch to the cored FSM:
///                       TLSClientHandshake<C>  (ClientHello / ServerHello / HRR)
///                       TLSClientAuthMachine<C> (EE … server Finished … client flight)
///                 ─► translate [TLSHandshakeAction] → bytes (encrypt at level)
///   send(Span)    ─► encrypt application data via the send protector
/// ```
///
/// The handshake FSM cores own the transcript + key schedule + all verification
/// (downgrade sentinel, CertificateVerify proof-of-possession, Finished MAC). The
/// engine owns the record layer (sequence numbers + the `TLSRecordSuiteProtector`
/// per direction), the message-reassembly buffer, and the negotiation/extension
/// assembly the cores expect the driver to perform. X.509 trust + CertificateVerify
/// signing are INJECTED (see ``TLSEngineConfiguration``); X.509 never enters here.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`, no
/// swift-crypto, no X509; typed throws (`TLSEngineError`); bare `catch { switch }`.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSHandshakeCore
import TLSRecordCore

public struct TLSClientEngine<C: CryptoProvider>: Sendable {

    // Stored state is `internal` (not `private`) so the per-file extensions
    // (`+Handshake`, `+Record`) that implement the dispatch and record layer can
    // mutate it. The type stays a value type; the facade holds it under its own
    // lock (caller-locked).

    // MARK: - Configuration

    let configuration: TLSEngineConfiguration<C>

    // MARK: - Handshake FSM (the cores)

    /// Pre-ServerHello FSM (ClientHello / ServerHello / HRR). `nil` once handed off
    /// to the authentication FSM.
    var preMachine: TLSClientHandshake<C>?
    /// Post-ServerHello authentication FSM. `nil` until ServerHello is processed.
    var authMachine: TLSClientAuthMachine<C>?

    // MARK: - Negotiation state owned by the driver

    /// The ephemeral key pair for the offered `key_share` (regenerated on HRR).
    var keyExchange: TLSKeyExchange<C>.EphemeralKeyPair?
    /// The exact session-id the ClientHello echoed (for SH echo validation).
    var legacySessionID: [UInt8]
    /// The cipher suites offered (for SH suite validation).
    var offeredCipherSuites: [CipherSuite]
    /// Whether a HelloRetryRequest has been processed (only one allowed).
    var receivedHelloRetryRequest: Bool
    /// The negotiated cipher suite (resolved at ServerHello).
    var negotiatedCipherSuite: CipherSuite
    /// The negotiated ALPN protocol, resolved in EncryptedExtensions.
    var negotiatedALPNValue: String?
    /// Whether the server requested a client certificate (mutual TLS).
    var clientCertificateRequested: Bool
    /// The peer's certificate-list DER bytes (for key resolution + validation).
    var peerCertificateListDER: [[UInt8]]
    /// Whether the peer presented a non-empty Certificate.
    var peerCertificatePresented: Bool
    /// Peer transport parameters (e.g. QUIC), surfaced post-handshake.
    public internal(set) var peerTransportParameters: [UInt8]?

    // MARK: - Record layer (driver-owned, caller-locked)

    /// The negotiated suite for record protection (set at the first keysAvailable).
    var recordCipherSuite: CipherSuite?
    var sendProtector: TLSRecordSuiteProtector<C>?
    var sendSequenceNumber: UInt64
    var receiveProtector: TLSRecordSuiteProtector<C>?
    var receiveSequenceNumber: UInt64

    // MARK: - Connection lifecycle

    enum Phase: Sendable, Equatable {
        case start
        case handshaking
        case connected
        case closed
        case failed
    }
    var phase: Phase

    /// Re-assembly buffer for partial handshake-message bytes at the current level.
    var handshakeBuffer: [UInt8]
    /// Re-assembly buffer for partial TLS records.
    var recordBuffer: [UInt8]

    /// Maximum re-assembly buffer size (256 KB) to bound DoS via partial messages.
    static var maxBufferSize: Int { 256 * 1024 }

    // MARK: - Initialization

    public init(configuration: TLSEngineConfiguration<C>) throws(TLSEngineError) {
        self.configuration = configuration
        self.preMachine = nil
        self.authMachine = nil
        self.keyExchange = nil
        self.legacySessionID = []
        self.offeredCipherSuites = []
        self.receivedHelloRetryRequest = false
        self.negotiatedCipherSuite = .tls_aes_128_gcm_sha256
        self.negotiatedALPNValue = nil
        self.clientCertificateRequested = false
        self.peerCertificateListDER = []
        self.peerCertificatePresented = false
        self.peerTransportParameters = nil
        self.recordCipherSuite = nil
        self.sendProtector = nil
        self.sendSequenceNumber = 0
        self.receiveProtector = nil
        self.receiveSequenceNumber = 0
        self.phase = .start
        self.handshakeBuffer = []
        self.recordBuffer = []
    }

    // MARK: - Accessors

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { phase == .connected }

    /// Whether the connection has been closed.
    public var isClosed: Bool { phase == .closed }

    /// The negotiated ALPN protocol, if any.
    public var negotiatedALPN: String? { negotiatedALPNValue }

    /// The peer's certificate chain (DER bytes, leaf first), or `nil`.
    public var peerCertificates: [[UInt8]]? {
        peerCertificateListDER.isEmpty ? nil : peerCertificateListDER
    }

    // MARK: - startHandshake

    /// Builds the ClientHello and returns the TLS record bytes to send.
    public mutating func startHandshake() throws(TLSEngineError) -> [UInt8] {
        guard phase == .start else {
            throw .internalError(reason: "Handshake already started")
        }
        phase = .handshaking

        // Ephemeral key for the first (preferred) group.
        guard let preferredGroup = configuration.supportedGroups.first else {
            throw .invalidConfiguration(reason: "no supported groups")
        }
        let keyPair: TLSKeyExchange<C>.EphemeralKeyPair
        do {
            keyPair = try TLSKeyExchange<C>.generate(for: preferredGroup)
        } catch {
            throw .protocolFailure(reason: "key generation failed: \(error)")
        }
        self.keyExchange = keyPair

        // Client random.
        let random = C.random.randomBytes(32)
        self.legacySessionID = []

        let extensions = try buildClientHelloExtensions(keyPair: keyPair)
        let suites = configuration.supportedCipherSuites
        self.offeredCipherSuites = suites

        // The main transcript suite is kept at SHA-256 (legacy-byte-identical).
        var pre = TLSClientHandshake<C>(cipherSuite: .tls_aes_128_gcm_sha256, pskOffered: false)
        let clientHello: [UInt8]
        do {
            (clientHello, _) = try pre.produceClientHello(
                random: random,
                legacySessionID: legacySessionID,
                cipherSuites: suites,
                extensions: extensions,
                offeredPsks: nil,
                pskBinder: nil,
                attemptEarlyData: false
            )
        } catch {
            phase = .failed
            throw .from(handshake: error)
        }
        self.preMachine = pre

        // ClientHello is sent as a plaintext handshake record at the initial level.
        return fragmentPlaintext(type: .handshake, content: clientHello)
    }

    /// Assembles the ClientHello extension list from the configuration.
    private func buildClientHelloExtensions(
        keyPair: TLSKeyExchange<C>.EphemeralKeyPair
    ) throws(TLSEngineError) -> [TLSExtension] {
        var extensions: [TLSExtension] = []
        extensions.append(.supportedVersionsClient([TLSConstants.version13]))
        extensions.append(.supportedGroupsList(configuration.supportedGroups))
        extensions.append(.signatureAlgorithmsList(configuration.advertisedSignatureSchemes))
        extensions.append(.keyShareClient([
            KeyShareEntry(group: keyPair.group, keyExchange: keyPair.publicKeyBytes),
        ]))
        if !configuration.alpnProtocols.isEmpty {
            extensions.append(.alpnProtocols(configuration.alpnProtocols))
        }
        if let serverName = configuration.serverName {
            extensions.append(.serverName(ServerNameExtension(hostName: serverName)))
        }
        if let params = configuration.transportParameters, !params.isEmpty {
            extensions.append(.transportParameters(params))
        }
        if configuration.localCertificateTypes != [.x509] {
            extensions.append(.clientCertificateTypes(configuration.localCertificateTypes))
        }
        if configuration.peerCertificateTypes != [.x509] {
            extensions.append(.serverCertificateTypes(configuration.peerCertificateTypes))
        }
        return extensions
    }

    // MARK: - receive

    /// Feeds received TLS byte-stream bytes and returns the aggregate effects.
    public mutating func receive(_ bytes: Span<UInt8>) throws(TLSEngineError) -> TLSEngineOutput {
        guard phase != .failed else {
            throw .protocolFailure(reason: "connection in failed state")
        }
        guard phase != .closed else {
            throw .connectionClosed
        }

        recordBuffer.append(contentsOf: bytes.facadeArrayLocal())
        guard recordBuffer.count <= Self.maxBufferSize else {
            phase = .failed
            throw .bufferOverflow
        }

        var output = TLSEngineOutput()
        do {
            try processRecords(into: &output)
        } catch {
            phase = .failed
            throw error
        }
        return output
    }

    /// Decodes and processes every complete record currently buffered.
    private mutating func processRecords(into output: inout TLSEngineOutput) throws(TLSEngineError) {
        while true {
            let decoded: (TLSRecord, Int)?
            do {
                decoded = try TLSRecordCodec.decode(from: recordBuffer)
            } catch {
                throw .protocolFailure(reason: "record decode failed: \(error)")
            }
            guard let (record, consumed) = decoded else { break }
            recordBuffer.removeFirst(consumed)

            let (contentType, payload) = try resolveRecord(record)
            switch contentType {
            case .handshake:
                try ingestHandshakeBytes(payload, into: &output)
            case .applicationData:
                output.applicationData.append(contentsOf: payload)
            case .alert:
                try handleAlert(payload, into: &output)
            case .changeCipherSpec:
                continue // RFC 8446 §5: ignore CCS (middlebox compatibility).
            }
        }
    }

    /// Resolves a record: decrypts if it is an encrypted application-data record.
    private mutating func resolveRecord(
        _ record: TLSRecord
    ) throws(TLSEngineError) -> (TLSContentType, [UInt8]) {
        if record.contentType == .applicationData {
            guard let protector = receiveProtector else {
                // RFC 8446 §5: app-data before encryption is active is a violation.
                throw .protocolFailure(reason: "unexpected plaintext application data")
            }
            let result: (content: [UInt8], type: TLSContentType)
            do {
                result = try protector.unprotect(
                    ciphertext: record.fragment,
                    sequenceNumber: receiveSequenceNumber
                )
            } catch {
                throw .verificationFailed(reason: "record decryption failed (bad MAC)")
            }
            receiveSequenceNumber &+= 1
            return (result.type, result.content)
        }

        if record.contentType == .changeCipherSpec {
            return (.changeCipherSpec, record.fragment)
        }

        // After encryption is active, handshake/alert MUST arrive encrypted.
        if receiveProtector != nil {
            switch record.contentType {
            case .handshake:
                throw .protocolFailure(reason: "unexpected plaintext handshake")
            case .alert:
                throw .protocolFailure(reason: "unexpected plaintext alert")
            default:
                break
            }
        }
        return (record.contentType, record.fragment)
    }

    /// Buffers handshake bytes and dispatches each complete message to the FSM.
    private mutating func ingestHandshakeBytes(
        _ payload: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        handshakeBuffer.append(contentsOf: payload)
        guard handshakeBuffer.count <= Self.maxBufferSize else {
            throw .bufferOverflow
        }

        var consumed = 0
        while (handshakeBuffer.count - consumed) >= 4 {
            let header = Array(handshakeBuffer[consumed..<(consumed + 4)])
            let parsed: (HandshakeType, Int)
            do {
                parsed = try HandshakeCodec.decodeHeader(from: header)
            } catch {
                throw .protocolFailure(reason: "handshake header decode failed: \(error)")
            }
            let totalLength = 4 + parsed.1
            guard (handshakeBuffer.count - consumed) >= totalLength else { break }

            let message = Array(handshakeBuffer[consumed..<(consumed + totalLength)])
            let content = Array(handshakeBuffer[(consumed + 4)..<(consumed + totalLength)])
            consumed += totalLength

            try processHandshakeMessage(
                type: parsed.0,
                content: content,
                rawMessage: message,
                into: &output
            )
        }
        if consumed > 0 {
            handshakeBuffer.removeFirst(consumed)
        }
    }

    // MARK: - Alerts

    private mutating func handleAlert(
        _ payload: [UInt8],
        into output: inout TLSEngineOutput
    ) throws(TLSEngineError) {
        let alert: TLSAlert
        do {
            alert = try TLSAlert.decode(from: payload)
        } catch {
            throw .protocolFailure(reason: "alert decode failed: \(error)")
        }
        if alert.alertDescription == .closeNotify {
            output.peerClosed = true
            phase = .closed
            return
        }
        if alert.level == .fatal {
            phase = .failed
            throw .fatalAlert(code: alert.alertDescription.rawValue, reason: alert.alertDescription.description)
        }
    }

    // MARK: - Private-state bridges (used by the +Handshake / +Record extensions)

    /// Records the peer's certificate-list DER (leaf first).
    mutating func setPeerCertificates(_ list: [[UInt8]]) {
        peerCertificateListDER = list
        peerCertificatePresented = !list.isEmpty
    }

    /// The peer's certificate-list DER (for key resolution / validation).
    func currentPeerCertificateListDER() -> [[UInt8]] { peerCertificateListDER }

    /// Marks the connection established.
    mutating func markConnected() { phase = .connected }

    /// Marks the connection closed.
    mutating func markClosed() { phase = .closed }
}
