/// The Embedded-clean, sans-IO TLS 1.3 SERVER connection engine.
///
/// `TLSServerEngine<C>` is the cored replacement for the host
/// `TLSConnection`+`TLS13Handler`+`ServerStateMachine` orchestration on the server
/// handshake/record path. Value type, caller-locked, sans-IO — the mirror of
/// ``TLSClientEngine``:
///
/// ```
///   receive(ClientHello)  ─► negotiate (suite/group/ALPN/cert types) + (EC)DHE
///                         ─► assemble SH/EE/CR/Cert wire bytes
///                         ─► drive TLSServerHandshake<C>.beginServerFlight
///                         ─► sign CertificateVerify (injected) + foldServerCertificateVerify
///                         ─► finishServerFlight → emit the server flight, install keys
///   receive(client Cert / CertVerify / Finished) ─► drive ingest* (mTLS,
///                         CertificateVerify proof-of-possession in-core, Finished MAC)
/// ```
///
/// Receive-key timing (RFC 8446): the server decrypts the client flight (Cert /
/// CertVerify / Finished) with the **client handshake** secret, then switches the
/// receive protector to the **client application** secret only AFTER the client
/// Finished is verified (the legacy `pendingReceiveKeys` deferral). Send keys move
/// to the **server application** secret immediately after the server flight.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`, no
/// swift-crypto, no X509; typed throws (`TLSEngineError`); bare `catch { switch }`.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSHandshakeCore
import TLSRecordCore

public struct TLSServerEngine<C: CryptoProvider>: Sendable {

    // MARK: - Configuration

    let configuration: TLSEngineConfiguration<C>

    // MARK: - Handshake FSM (the core)

    var serverMachine: TLSServerHandshake<C>?

    // MARK: - Negotiation state owned by the driver

    var negotiatedCipherSuite: CipherSuite
    var negotiatedALPNValue: String?
    var negotiatedServerCertType: CertificateType
    var negotiatedClientCertType: CertificateType
    var clientSignatureAlgorithms: [TLSWireCore.SignatureScheme]?
    var requestedClientCertificate: Bool
    var certificateRequestContext: [UInt8]
    var sentHelloRetryRequest: Bool
    var helloRetryRequestGroup: NamedGroup?
    var clientCertificateListDER: [[UInt8]]
    var clientHelloPeerKey: (bytes: [UInt8], scheme: TLSWireCore.SignatureScheme)?
    /// The validated peer's application identifier bytes (e.g. an encoded libp2p
    /// PeerID), returned by the injected `validateCertificate` strategy. `nil` until
    /// the validator runs, or when it established trust without an identifier.
    var validatedPeerIdentifier: [UInt8]?
    public internal(set) var peerTransportParameters: [UInt8]?

    // MARK: - Record layer (driver-owned, caller-locked)

    var recordCipherSuite: CipherSuite?
    var sendProtector: TLSRecordSuiteProtector<C>?
    var sendSequenceNumber: UInt64
    var receiveProtector: TLSRecordSuiteProtector<C>?
    var receiveSequenceNumber: UInt64
    /// The deferred client APPLICATION receive secret, installed on client Finished
    /// (the server keeps client HANDSHAKE receive keys until then).
    var pendingClientApplicationSecret: [UInt8]?

    // MARK: - Connection lifecycle

    enum Phase: Sendable, Equatable {
        case start
        case sentHelloRetryRequest
        case waitClientCertificate
        case waitClientCertificateVerify
        case waitFinished
        case connected
        case closed
        case failed
    }
    var phase: Phase

    var handshakeBuffer: [UInt8]
    var recordBuffer: [UInt8]

    static var maxBufferSize: Int { 256 * 1024 }

    // MARK: - Initialization

    public init(configuration: TLSEngineConfiguration<C>) throws(TLSEngineError) {
        // A server requires identity material (signer + chain) to authenticate.
        guard configuration.sign != nil, configuration.signingScheme != nil else {
            throw .invalidConfiguration(reason: "server requires a signing identity")
        }
        self.configuration = configuration
        self.serverMachine = nil
        self.negotiatedCipherSuite = .tls_aes_128_gcm_sha256
        self.negotiatedALPNValue = nil
        self.negotiatedServerCertType = .x509
        self.negotiatedClientCertType = .x509
        self.clientSignatureAlgorithms = nil
        self.requestedClientCertificate = false
        self.certificateRequestContext = []
        self.sentHelloRetryRequest = false
        self.helloRetryRequestGroup = nil
        self.clientCertificateListDER = []
        self.clientHelloPeerKey = nil
        self.validatedPeerIdentifier = nil
        self.peerTransportParameters = nil
        self.recordCipherSuite = nil
        self.sendProtector = nil
        self.sendSequenceNumber = 0
        self.receiveProtector = nil
        self.receiveSequenceNumber = 0
        self.pendingClientApplicationSecret = nil
        self.phase = .start
        self.handshakeBuffer = []
        self.recordBuffer = []
    }

    // MARK: - Accessors

    public var isEstablished: Bool { phase == .connected }
    public var isClosed: Bool { phase == .closed }
    public var negotiatedALPN: String? { negotiatedALPNValue }
    public var peerCertificates: [[UInt8]]? {
        clientCertificateListDER.isEmpty ? nil : clientCertificateListDER
    }

    /// The validated peer's application identifier bytes (e.g. an encoded libp2p
    /// PeerID) produced by the injected certificate validator, or `nil` when no
    /// validator ran or it established trust without an identifier.
    public var peerIdentifier: [UInt8]? { validatedPeerIdentifier }

    // MARK: - startHandshake

    /// A server emits nothing until the ClientHello arrives.
    public mutating func startHandshake() throws(TLSEngineError) -> [UInt8] {
        guard phase == .start else {
            throw .internalError(reason: "Handshake already started")
        }
        return []
    }

    // MARK: - receive

    public mutating func receive(_ bytes: Span<UInt8>) throws(TLSEngineError) -> TLSEngineOutput {
        guard phase != .failed else { throw .protocolFailure(reason: "connection in failed state") }
        guard phase != .closed else { throw .connectionClosed }

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
                continue
            }
        }
    }

    private mutating func resolveRecord(
        _ record: TLSRecord
    ) throws(TLSEngineError) -> (TLSContentType, [UInt8]) {
        if record.contentType == .applicationData {
            guard let protector = receiveProtector else {
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

            let content = Array(handshakeBuffer[(consumed + 4)..<(consumed + totalLength)])
            consumed += totalLength
            try processHandshakeMessage(type: parsed.0, content: content, into: &output)
        }
        if consumed > 0 {
            handshakeBuffer.removeFirst(consumed)
        }
    }

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

    // MARK: - Private-state bridges (used by +Handshake / +Record)

    mutating func setClientCertificates(_ list: [[UInt8]]) {
        clientCertificateListDER = list
    }
    func currentClientCertificateListDER() -> [[UInt8]] { clientCertificateListDER }
    mutating func markConnected() { phase = .connected }
    mutating func markClosed() { phase = .closed }
}
