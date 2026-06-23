/// TLS 1.3 Handler - Main Implementation of TLS13Provider
///
/// Implements the TLS13Provider protocol using pure Swift and swift-crypto.
/// Designed for use without a TLS record layer.

import Foundation
import Crypto
import Synchronization
import TLSWireCore
import TLSCryptoCore
import TLSHandshakeCore

// MARK: - TLS 1.3 Handler

/// Pure Swift TLS 1.3 implementation
public final class TLS13Handler: TLSTransportParameterProvider, Sendable {

    /// Maximum size for handshake message buffers per encryption level.
    /// Default maximum handshake buffer size (256KB).
    /// 256KB accommodates large certificate chains (cross-signed, 4096-bit RSA)
    /// while still providing DoS protection against unbounded buffer growth.
    private static let defaultMaxBufferSize = 262144

    private let state = Mutex<HandlerState>(HandlerState())
    private let configuration: TLSConfiguration

    private struct HandlerState: Sendable {
        var isClientMode: Bool = true
        var clientStateMachine: ClientStateMachine?
        var serverStateMachine: ServerStateMachine?
        var localTransportParams: Data?
        var peerTransportParams: Data?
        var negotiatedALPN: String?
        var handshakeComplete: Bool = false

        // Buffer for partial message reassembly (per encryption level)
        var messageBuffers: [TLSEncryptionLevel: Data] = [:]

        // Application secrets for key update
        var clientApplicationSecret: SymmetricKey?
        var serverApplicationSecret: SymmetricKey?
        var keySchedule: TLSKeySchedule = TLSKeySchedule()

        // Exporter master secret (RFC 8446 Section 7.5)
        var exporterMasterSecret: SymmetricKey?

        // Key phase counter (number of key updates performed)
        var keyPhase: UInt8 = 0

        // Session resumption configuration (set before startHandshake)
        var resumptionTicket: SessionTicketData?
        var attemptEarlyData: Bool = false

        // 0-RTT state tracking
        var is0RTTAttempted: Bool = false
        var is0RTTAccepted: Bool = false
    }

    // MARK: - Initialization

    public init(configuration: TLSConfiguration = TLSConfiguration()) {
        self.configuration = configuration
    }

    // MARK: - TLS13Provider Protocol

    public func startHandshake(isClient: Bool) async throws -> [TLSOutput] {
        try configuration.validate()

        return try state.withLock { state in
            state.isClientMode = isClient

            if isClient {
                let clientMachine = ClientStateMachine()
                state.clientStateMachine = clientMachine

                // Pass session ticket and early data flag to ClientStateMachine
                let (clientHello, outputs) = try clientMachine.startHandshake(
                    configuration: configuration,
                    transportParameters: state.localTransportParams,
                    sessionTicket: state.resumptionTicket,
                    attemptEarlyData: state.attemptEarlyData
                )

                // Track if 0-RTT was attempted
                state.is0RTTAttempted = state.attemptEarlyData && state.resumptionTicket != nil

                var result = outputs
                result.insert(.handshakeData(clientHello, level: .initial), at: 0)
                return result
            } else {
                let serverMachine = ServerStateMachine(configuration: configuration, sessionTicketStore: configuration.sessionTicketStore)
                state.serverStateMachine = serverMachine
                return []  // Server waits for ClientHello
            }
        }
    }

    public func processHandshakeData(_ data: Data, at level: TLSEncryptionLevel) async throws -> [TLSOutput] {
        return try state.withLock { state in
            // Append to level-specific buffer
            var buffer = state.messageBuffers[level] ?? Data()
            buffer.append(data)

            // Check buffer size limit to prevent DoS
            let maxSize = configuration.maxHandshakeBufferSize ?? Self.defaultMaxBufferSize
            guard buffer.count <= maxSize else {
                throw TLSError.internalError("Handshake buffer exceeded maximum size")
            }

            var outputs: [TLSOutput] = []

            // Track consumed bytes to avoid O(n) copy per message.
            // We trim the buffer once at the end instead of on each iteration.
            var consumed = 0

            // Process complete messages from buffer
            while (buffer.count - consumed) >= 4 {
                // Parse handshake header from current position
                let headerStart = buffer.index(buffer.startIndex, offsetBy: consumed)
                let headerData = Data(buffer[headerStart..<buffer.index(headerStart, offsetBy: 4)])
                let (messageType, contentLength) = try HandshakeCodec.decodeHeader(from: headerData)
                let totalLength = 4 + contentLength

                guard (buffer.count - consumed) >= totalLength else {
                    // Need more data
                    if outputs.isEmpty {
                        outputs.append(.needMoreData)
                    }
                    break
                }

                // Extract message content
                let contentStart = buffer.index(headerStart, offsetBy: 4)
                let contentEnd = buffer.index(headerStart, offsetBy: totalLength)
                let content = Data(buffer[contentStart..<contentEnd])
                consumed += totalLength

                // Process the message
                let messageOutputs = try processMessage(
                    type: messageType,
                    content: content,
                    level: level,
                    state: &state
                )
                outputs.append(contentsOf: messageOutputs)
            }

            // Trim consumed bytes once (O(remaining) instead of O(N × remaining))
            if consumed > 0 {
                buffer = Data(buffer.dropFirst(consumed))
            }

            // Store updated buffer
            state.messageBuffers[level] = buffer

            return outputs
        }
    }

    public func getLocalTransportParameters() -> Data {
        state.withLock { $0.localTransportParams ?? Data() }
    }

    public func setLocalTransportParameters(_ params: Data) throws {
        state.withLock { $0.localTransportParams = params }
    }

    public func getPeerTransportParameters() -> Data? {
        state.withLock { $0.peerTransportParams }
    }

    public var isHandshakeComplete: Bool {
        state.withLock { $0.handshakeComplete }
    }

    public var isClient: Bool {
        state.withLock { $0.isClientMode }
    }

    public var negotiatedALPN: String? {
        state.withLock { $0.negotiatedALPN }
    }

    public func configureResumption(ticket: SessionTicketData, attemptEarlyData: Bool) throws {
        state.withLock { state in
            state.resumptionTicket = ticket
            state.attemptEarlyData = attemptEarlyData
        }
    }

    public var is0RTTAccepted: Bool {
        state.withLock { $0.is0RTTAccepted }
    }

    public var is0RTTAttempted: Bool {
        state.withLock { $0.is0RTTAttempted }
    }

    /// Peer certificates (raw DER data, leaf certificate first)
    /// Available after receiving peer's Certificate message.
    /// For client mode: returns server's certificates
    /// For server mode (mTLS): returns client's certificates
    public var peerCertificates: [Data]? {
        state.withLock { state -> [Data]? in
            if state.isClientMode {
                return state.clientStateMachine?.peerCertificates
            } else {
                // For server in mTLS, the peer is the client
                // Client certificates are stored in clientCertificates, not peerCertificates
                return state.serverStateMachine?.clientCertificates
            }
        }
    }

    /// Parsed peer leaf certificate
    /// Available after receiving peer's Certificate message.
    /// For client mode: returns server's certificate
    /// For server mode (mTLS): returns client's certificate
    public var peerCertificate: X509Certificate? {
        state.withLock { state -> X509Certificate? in
            if state.isClientMode {
                return state.clientStateMachine?.peerCertificate
            } else {
                // For server in mTLS, the peer is the client
                return state.serverStateMachine?.clientCertificate
            }
        }
    }

    /// Validated peer info from certificate validator callback.
    ///
    /// This contains the value returned by `TLSConfiguration.certificateValidator`
    /// after successful certificate validation (e.g., PeerID for libp2p).
    public var validatedPeerInfo: (any Sendable)? {
        state.withLock { state in
            if state.isClientMode {
                return state.clientStateMachine?.validatedPeerInfo
            } else {
                return state.serverStateMachine?.validatedPeerInfo
            }
        }
    }

    /// Whether PSK (pre-shared key) was used for this handshake.
    ///
    /// Returns `true` when the handshake completed with PSK-based authentication
    /// instead of certificate-based authentication. Available after handshake completion.
    public var pskUsed: Bool {
        state.withLock { state in
            if state.isClientMode {
                return state.clientStateMachine?.pskUsed ?? false
            } else {
                return state.serverStateMachine?.pskUsed ?? false
            }
        }
    }

    public func requestKeyUpdate() async throws -> [TLSOutput] {
        // Key update implementation (RFC 8446 Section 4.6.3)
        return try state.withLock { state in
            guard state.handshakeComplete else {
                throw TLSError.unexpectedMessage("Cannot request key update before handshake complete")
            }

            let currentSendSecret: SymmetricKey?
            if state.isClientMode {
                currentSendSecret = state.clientApplicationSecret
            } else {
                currentSendSecret = state.serverApplicationSecret
            }

            guard let sendSecret = currentSendSecret else {
                throw TLSError.internalError("Application secrets not available for key update")
            }

            // Build KeyUpdate message (request peer to update too)
            let keyUpdate = KeyUpdate(requestUpdate: .updateRequested)
            let encoded = keyUpdate.encodeAsHandshake()

            // Emit the KeyUpdate message first (encrypted with current keys)
            var outputs: [TLSOutput] = [
                .handshakeData(encoded, level: .application)
            ]

            // Derive next send secret
            let nextSendSecret = state.keySchedule.nextApplicationSecret(from: sendSecret)

            // Update stored send secret only
            if state.isClientMode {
                state.clientApplicationSecret = nextSendSecret
            } else {
                state.serverApplicationSecret = nextSendSecret
            }
            state.keyPhase = (state.keyPhase + 1) % 2

            let cipherSuite = state.keySchedule.cipherSuite

            // Emit keysAvailable with only the send secret updated
            // Receive keys remain unchanged until peer's KeyUpdate arrives
            if state.isClientMode {
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: nextSendSecret,
                    serverSecret: nil,
                    cipherSuite: cipherSuite
                )))
            } else {
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: nil,
                    serverSecret: nextSendSecret,
                    cipherSuite: cipherSuite
                )))
            }

            return outputs
        }
    }

    /// Current key phase (0 or 1, toggles with each key update)
    public var keyPhase: UInt8 {
        state.withLock { $0.keyPhase }
    }

    public func exportKeyingMaterial(
        label: String,
        context: Data?,
        length: Int
    ) throws -> Data {
        // RFC 8446 Section 7.5: Exporters
        // Delegates to TLSKeySchedule which handles cipher-suite-appropriate hashing
        try state.withLock { state in
            guard state.handshakeComplete else {
                throw TLSError.unexpectedMessage("Cannot export keying material before handshake complete")
            }

            guard let exporterMasterSecret = state.exporterMasterSecret else {
                throw TLSError.internalError("Exporter master secret not available")
            }

            return state.keySchedule.exportKeyingMaterial(
                exporterMasterSecret: exporterMasterSecret,
                label: label,
                context: context,
                length: length
            )
        }
    }

    // MARK: - Private Helpers

    /// Validates that a handshake message is received at the correct encryption level
    /// per RFC 8446
    private func validateTLSEncryptionLevel(
        type: HandshakeType,
        level: TLSEncryptionLevel,
        isClient: Bool
    ) throws {
        let expectedLevel: TLSEncryptionLevel
        switch type {
        case .clientHello, .serverHello:
            expectedLevel = .initial
        case .endOfEarlyData:
            // RFC 8446 Section 2.3: EndOfEarlyData is encrypted under
            // client_early_traffic_secret (0-RTT keys), shown as (EndOfEarlyData)
            expectedLevel = .earlyData
        case .encryptedExtensions, .certificateRequest, .certificate, .certificateVerify, .finished:
            expectedLevel = .handshake
        case .keyUpdate, .newSessionTicket:
            expectedLevel = .application
        default:
            // Unknown types are handled elsewhere
            return
        }

        guard level == expectedLevel else {
            throw TLSError.unexpectedMessage(
                "Message \(type) received at \(level) level, expected \(expectedLevel)"
            )
        }
    }

    private func processMessage(
        type: HandshakeType,
        content: Data,
        level: TLSEncryptionLevel,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        // Validate encryption level per RFC 8446
        try validateTLSEncryptionLevel(type: type, level: level, isClient: state.isClientMode)

        if state.isClientMode {
            return try processClientMessage(type: type, content: content, level: level, state: &state)
        } else {
            return try processServerMessage(type: type, content: content, level: level, state: &state)
        }
    }

    private func processClientMessage(
        type: HandshakeType,
        content: Data,
        level: TLSEncryptionLevel,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        guard let clientMachine = state.clientStateMachine else {
            throw TLSError.internalError("Client state machine not initialized")
        }

        var outputs: [TLSOutput] = []

        switch type {
        case .serverHello:
            outputs = try clientMachine.processServerHello(content)

        case .encryptedExtensions:
            outputs = try clientMachine.processEncryptedExtensions(content)
            // Extract peer transport params
            if let params = clientMachine.peerTransportParameters {
                state.peerTransportParams = params
            }
            // Update 0-RTT acceptance status from client state machine
            if state.is0RTTAttempted {
                state.is0RTTAccepted = clientMachine.earlyDataAccepted
            }

        case .certificateRequest:
            // Server requesting client certificate (mutual TLS)
            outputs = try clientMachine.processCertificateRequest(content)

        case .certificate:
            outputs = try clientMachine.processCertificate(content)

        case .certificateVerify:
            outputs = try clientMachine.processCertificateVerify(content)

        case .finished:
            outputs = try clientMachine.processServerFinished(content)

            // Extract application secrets from outputs for key update support
            for output in outputs {
                if case .keysAvailable(let info) = output, info.level == .application {
                    state.clientApplicationSecret = info.clientSecret
                    state.serverApplicationSecret = info.serverSecret
                }
            }

            // Extract exporter master secret
            state.exporterMasterSecret = clientMachine.exporterMasterSecret

            // Update state
            state.negotiatedALPN = clientMachine.negotiatedALPN
            state.handshakeComplete = true

        case .keyUpdate:
            outputs = try processKeyUpdate(content: content, state: &state)

        case .newSessionTicket:
            outputs = try processNewSessionTicket(content: content, state: &state)

        default:
            throw TLSError.unexpectedMessage("Unexpected message type \(type) for client")
        }

        return outputs
    }

    private func processServerMessage(
        type: HandshakeType,
        content: Data,
        level: TLSEncryptionLevel,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        guard let serverMachine = state.serverStateMachine else {
            throw TLSError.internalError("Server state machine not initialized")
        }

        var outputs: [TLSOutput] = []

        switch type {
        case .clientHello:
            let (response, clientHelloOutputs) = try serverMachine.processClientHello(
                content,
                transportParameters: state.localTransportParams
            )
            outputs = clientHelloOutputs

            // Extract peer transport params
            if let params = serverMachine.peerTransportParameters {
                state.peerTransportParams = params
            }

            // Extract application secrets from outputs for key update support
            for output in clientHelloOutputs {
                if case .keysAvailable(let info) = output, info.level == .application {
                    state.clientApplicationSecret = info.clientSecret
                    state.serverApplicationSecret = info.serverSecret
                }
            }

            // Extract exporter master secret
            state.exporterMasterSecret = serverMachine.exporterMasterSecret

            // Add all server messages to outputs
            for (data, msgLevel) in response.messages {
                outputs.insert(.handshakeData(data, level: msgLevel), at: outputs.count - clientHelloOutputs.count)
            }

        case .certificate:
            // Client's certificate (for mutual TLS)
            outputs = try serverMachine.processClientCertificate(content)

        case .certificateVerify:
            // Client's CertificateVerify (for mutual TLS)
            outputs = try serverMachine.processClientCertificateVerify(content)

        case .finished:
            let finishedOutputs = try serverMachine.processClientFinished(content)
            outputs = finishedOutputs

            // Update state
            state.negotiatedALPN = serverMachine.negotiatedALPN
            state.handshakeComplete = true

        case .endOfEarlyData:
            // Client signals end of 0-RTT data (RFC 8446 Section 4.5)
            outputs = try serverMachine.processEndOfEarlyData(content)

        case .keyUpdate:
            outputs = try processKeyUpdate(content: content, state: &state)

        default:
            throw TLSError.unexpectedMessage("Unexpected message type \(type) for server")
        }

        return outputs
    }

    // MARK: - Post-Handshake Messages

    /// Process a received KeyUpdate message (RFC 8446 Section 4.6.3)
    ///
    /// When we receive KeyUpdate from the peer:
    /// 1. Update our receive keys (peer's send direction = our receive direction)
    /// 2. If peer requested an update, respond with our own KeyUpdate and update our send keys
    private func processKeyUpdate(
        content: Data,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        guard state.handshakeComplete else {
            throw TLSError.unexpectedMessage("KeyUpdate before handshake complete")
        }

        let keyUpdate = try KeyUpdate.decode(from: content)

        // Derive next receive secret (peer updated their send keys)
        let currentReceiveSecret: SymmetricKey?
        if state.isClientMode {
            currentReceiveSecret = state.serverApplicationSecret
        } else {
            currentReceiveSecret = state.clientApplicationSecret
        }

        guard let recvSecret = currentReceiveSecret else {
            throw TLSError.internalError("Application secrets not available for key update")
        }

        let nextReceiveSecret = state.keySchedule.nextApplicationSecret(from: recvSecret)
        let cipherSuite = state.keySchedule.cipherSuite

        // Update stored receive secret
        if state.isClientMode {
            state.serverApplicationSecret = nextReceiveSecret
        } else {
            state.clientApplicationSecret = nextReceiveSecret
        }

        var outputs: [TLSOutput] = []

        // Emit keysAvailable with only receive secret updated
        if state.isClientMode {
            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .application,
                clientSecret: nil,
                serverSecret: nextReceiveSecret,
                cipherSuite: cipherSuite
            )))
        } else {
            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .application,
                clientSecret: nextReceiveSecret,
                serverSecret: nil,
                cipherSuite: cipherSuite
            )))
        }

        // If peer requested an update, respond with our own KeyUpdate
        if keyUpdate.requestUpdate == .updateRequested {
            let response = KeyUpdate(requestUpdate: .updateNotRequested)
            let encoded = response.encodeAsHandshake()

            // Send response (encrypted with current send keys)
            outputs.append(.handshakeData(encoded, level: .application))

            // Update our send keys
            let currentSendSecret: SymmetricKey?
            if state.isClientMode {
                currentSendSecret = state.clientApplicationSecret
            } else {
                currentSendSecret = state.serverApplicationSecret
            }

            guard let sendSecret = currentSendSecret else {
                throw TLSError.internalError("Application secrets not available for key update")
            }

            let nextSendSecret = state.keySchedule.nextApplicationSecret(from: sendSecret)

            if state.isClientMode {
                state.clientApplicationSecret = nextSendSecret
            } else {
                state.serverApplicationSecret = nextSendSecret
            }

            // Emit keysAvailable for send direction
            if state.isClientMode {
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: nextSendSecret,
                    serverSecret: nil,
                    cipherSuite: cipherSuite
                )))
            } else {
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .application,
                    clientSecret: nil,
                    serverSecret: nextSendSecret,
                    cipherSuite: cipherSuite
                )))
            }
        }

        return outputs
    }

    /// Process a received NewSessionTicket message (RFC 8446 Section 4.6.1)
    ///
    /// Only valid for clients receiving post-handshake tickets from the server.
    private func processNewSessionTicket(
        content: Data,
        state: inout HandlerState
    ) throws -> [TLSOutput] {
        guard state.handshakeComplete else {
            throw TLSError.unexpectedMessage("NewSessionTicket before handshake complete")
        }
        guard state.isClientMode else {
            throw TLSError.unexpectedMessage("Server received NewSessionTicket")
        }

        let ticket = try NewSessionTicket.decode(from: content)
        let cipherSuite = state.keySchedule.cipherSuite

        // The resumption master secret is needed to derive the PSK
        guard let clientMachine = state.clientStateMachine,
              let resumptionMasterSecret = clientMachine.resumptionMasterSecret else {
            throw TLSError.internalError("Resumption master secret not available")
        }

        return [
            .newSessionTicket(NewSessionTicketInfo(
                ticket: ticket,
                resumptionMasterSecret: resumptionMasterSecret,
                cipherSuite: cipherSuite,
                alpn: state.negotiatedALPN
            ))
        ]
    }
}

// MARK: - Server State Machine

/// Server-side TLS 1.3 state machine
public final class ServerStateMachine: Sendable {

    private let state = Mutex<ServerState>(ServerState())
    private let configuration: TLSConfiguration
    private let sessionTicketStore: SessionTicketStore?

    private struct ServerState: Sendable {
        var handshakeState: ServerHandshakeState = .start
        var context: HandshakeContext = HandshakeContext()

        /// The Embedded-clean server handshake FSM: owns the transcript + key
        /// schedule from ClientHello through the client Finished (binder validation,
        /// HRR transform, (EC)DHE + handshake/application-secret derivation, server
        /// Finished, client CertificateVerify/Finished verification). The adapter
        /// drives it under the `Mutex` and keeps config negotiation, X.509, the
        /// MLKEM hybrid, and `any TLSSigningKey` signing.
        var serverMachine: TLSServerHandshake<TLSFoundationProvider>?
    }

    public init(configuration: TLSConfiguration, sessionTicketStore: SessionTicketStore? = nil) {
        self.configuration = configuration
        self.sessionTicketStore = sessionTicketStore
    }

    // MARK: - FSM Bridging Helpers

    /// Raw bytes of a `SymmetricKey` for handing secrets to the byte-based core.
    private static func secretBytes(_ key: SymmetricKey) -> [UInt8] {
        key.withUnsafeBytes { [UInt8]($0) }
    }

    /// Wraps raw secret bytes from the core back into a `SymmetricKey`.
    private static func symmetricKey(_ bytes: [UInt8]) -> SymmetricKey {
        SymmetricKey(data: Data(bytes))
    }

    /// Response from processing ClientHello
    public struct ClientHelloResponse: Sendable {
        public let messages: [(Data, TLSEncryptionLevel)]
    }

    /// Process ClientHello and generate server response
    public func processClientHello(
        _ data: Data,
        transportParameters: Data? = nil
    ) throws -> (response: ClientHelloResponse, outputs: [TLSOutput]) {
        return try state.withLock { state in
            // Check if this is ClientHello2 (after HelloRetryRequest)
            let isClientHello2 = state.handshakeState == .sentHelloRetryRequest

            guard state.handshakeState == .start || isClientHello2 else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected ClientHello")
            }

            // Initialize the Embedded-clean server FSM on the first ClientHello. Its
            // main transcript uses the default suite (matching the legacy default
            // `TranscriptHash()`); the binder / PSK early-secret use their own
            // ticket-suite hash. After a HelloRetryRequest the existing machine
            // (which already folded message_hash(CH1) + HRR) is reused.
            if state.serverMachine == nil {
                state.serverMachine = TLSServerHandshake<TLSFoundationProvider>()
            }

            let clientHello = try ClientHello.decode(from: data)

            // RFC 8446 Section 4.2.11: pre_shared_key MUST be the last extension
            // in ClientHello. Servers MUST check this and abort with illegal_parameter
            // if not satisfied.
            if clientHello.preSharedKey != nil {
                guard clientHello.extensions.last?.extensionType == .preSharedKey else {
                    throw TLSHandshakeError.invalidExtension(
                        "pre_shared_key must be the last extension in ClientHello"
                    )
                }
            }

            // Verify TLS 1.3 support
            guard let supportedVersions = clientHello.supportedVersions,
                  supportedVersions.supportsTLS13 else {
                throw TLSHandshakeError.unsupportedVersion
            }

            // Find common cipher suite (server preference order)
            let serverPreferred = configuration.supportedCipherSuites
            guard let selectedCipherSuite = serverPreferred.first(where: {
                clientHello.cipherSuites.contains($0)
            }) else {
                throw TLSHandshakeError.noCipherSuiteMatch
            }

            // RFC 8446 Section 4.1.4: ClientHello2 cipher suite must be
            // consistent with the cipher suite selected in HelloRetryRequest.
            // Violation sends illegal_parameter alert.
            if isClientHello2 {
                guard selectedCipherSuite == state.context.cipherSuite else {
                    throw TLSHandshakeError.invalidExtension(
                        "ClientHello2 cipher suite inconsistent with HelloRetryRequest"
                    )
                }
            }
            state.context.cipherSuite = selectedCipherSuite

            // Store client's signature_algorithms for later validation (RFC 8446 Section 4.4.3)
            for ext in clientHello.extensions {
                if case .signatureAlgorithms(let sigAlgs) = ext {
                    state.context.peerSignatureAlgorithms = sigAlgs.supportedSignatureAlgorithms
                    break
                }
            }

            // Get client's key share extension
            guard let clientKeyShare = clientHello.keyShare else {
                throw TLSHandshakeError.noKeyShareMatch
            }

            // Negotiate key exchange group
            let serverSupportedGroups = configuration.supportedGroups
            var selectedGroup: NamedGroup?
            var selectedKeyShareEntry: KeyShareEntry?

            if isClientHello2 {
                // ClientHello2: Must use the group we requested in HRR
                guard let requestedGroup = state.context.helloRetryRequestGroup,
                      let entry = clientKeyShare.keyShare(for: requestedGroup) else {
                    throw TLSHandshakeError.noKeyShareMatch
                }
                selectedGroup = requestedGroup
                selectedKeyShareEntry = entry
            } else {
                // ClientHello1: Find first server-preferred group that client offers
                for group in serverSupportedGroups {
                    if let entry = clientKeyShare.keyShare(for: group) {
                        selectedGroup = group
                        selectedKeyShareEntry = entry
                        break
                    }
                }

                // If no matching key share, try to send HelloRetryRequest
                if selectedGroup == nil {
                    // Check if client supports any of our groups
                    let clientSupportedGroups = clientHello.supportedGroups?.namedGroups ?? []
                    // RFC 8446 Section 4.1.4: The server MUST NOT request a group
                    // that the client already provided a key_share for.
                    let clientKeyShareGroups = Set(clientKeyShare.clientShares.map { $0.group })
                    if let commonGroup = serverSupportedGroups.first(where: {
                        clientSupportedGroups.contains($0) && !clientKeyShareGroups.contains($0)
                    }) {
                        return try sendHelloRetryRequest(
                            clientHello: clientHello,
                            clientHelloData: data,
                            requestedGroup: commonGroup,
                            state: &state
                        )
                    }
                    throw TLSHandshakeError.noKeyShareMatch
                }
            }

            guard let selectedGroup = selectedGroup,
                  let peerKeyShareEntry = selectedKeyShareEntry else {
                throw TLSHandshakeError.noKeyShareMatch
            }

            // Extract transport parameters (optional)
            if let peerTransportParams = clientHello.transportParameters {
                state.context.peerTransportParameters = Data(peerTransportParams)
            }
            state.context.localTransportParameters = transportParameters

            // Store client values
            state.context.clientRandom = Data(clientHello.random)
            state.context.sessionID = Data(clientHello.legacySessionID)

            // Try PSK validation if offered
            var pskValidationResult: PSKValidationResult = .noPskOffered
            var selectedPskIndex: UInt16? = nil

            if let offeredPsks = clientHello.preSharedKey,
               let store = self.sessionTicketStore {
                // Compute truncated transcript for binder validation
                // ClientHello without binders section
                let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: data)
                let bindersSize = offeredPsks.bindersSize
                let truncatedLength = clientHelloMessage.count - bindersSize
                let truncatedTranscript = clientHelloMessage.prefix(truncatedLength)

                // Try each offered PSK identity
                for (index, identity) in offeredPsks.identities.enumerated() {
                    guard let session = store.lookupSession(ticketId: Data(identity.identity)) else {
                        continue
                    }

                    // Validate ticket age
                    guard session.isValidAge(obfuscatedAge: identity.obfuscatedTicketAge) else {
                        continue
                    }

                    // Get the corresponding binder
                    guard index < offeredPsks.binders.count else {
                        continue
                    }
                    let binder = offeredPsks.binders[index]

                    // Derive PSK from session using the stored ticket nonce
                    let ticketNonce = session.ticketNonce

                    // Initialize key schedule with PSK (used only to derive the PSK
                    // for the session; the binder check itself runs in the core).
                    let pskKeySchedule = TLSKeySchedule(cipherSuite: session.cipherSuite)
                    let psk = session.derivePSK(ticketNonce: ticketNonce, keySchedule: pskKeySchedule)

                    // Validate the binder through the Embedded-clean core (the seam
                    // HMAC path; byte-identical to the legacy PSKBinderHelper). The
                    // binder is computed over the truncated ClientHello hashed with
                    // the session's cipher suite.
                    let binderValid: Bool
                    do {
                        binderValid = try TLSServerHandshake<TLSFoundationProvider>.isValidPSKBinder(
                            psk: Self.secretBytes(psk),
                            cipherSuite: session.cipherSuite,
                            truncatedClientHello: [UInt8](truncatedTranscript),
                            offeredBinder: [UInt8](binder),
                            isResumption: true
                        )
                    } catch {
                        continue
                    }
                    if binderValid {
                        // PSK validated successfully
                        selectedPskIndex = UInt16(index)
                        state.context.pskUsed = true
                        state.context.selectedPskIdentity = UInt16(index)
                        state.context.cipherSuite = session.cipherSuite
                        pskValidationResult = .valid(index: UInt16(index), session: session, psk: psk)
                        break
                    }
                }
            }

            // The complete ClientHello handshake message (folded by the core).
            let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: data)

            // Decide PSK early-secret material and 0-RTT acceptance adapter-side
            // (config + replay protection). The early secret / early-traffic-secret
            // derivation and the transcript folding move to the core.
            var acceptedPSK: TLSServerHandshake<TLSFoundationProvider>.AcceptedPSK?
            var earlyDataAccepted = false
            if selectedPskIndex != nil,
               case .valid(_, let session, let psk) = pskValidationResult {
                acceptedPSK = TLSServerHandshake<TLSFoundationProvider>.AcceptedPSK(
                    psk: Self.secretBytes(psk),
                    cipherSuite: session.cipherSuite
                )

                // Check if client offered early_data and session allows it
                if clientHello.earlyData && session.maxEarlyDataSize > 0 {
                    // Check replay protection if configured (RFC 8446 Section 8)
                    // 0-RTT data can be replayed, so servers should track ticket usage
                    var acceptEarlyData = true
                    if let replayProtection = configuration.replayProtection {
                        // Create ticket identifier from ticket nonce (unique per ticket)
                        let ticketIdentifier = ReplayProtection.createIdentifier(from: session.ticketNonce)
                        acceptEarlyData = replayProtection.shouldAcceptEarlyData(ticketIdentifier: ticketIdentifier)
                    }

                    if acceptEarlyData {
                        // Accept early data
                        state.context.earlyDataState.attemptingEarlyData = true
                        state.context.earlyDataState.earlyDataAccepted = true
                        state.context.earlyDataState.maxEarlyDataSize = session.maxEarlyDataSize
                        earlyDataAccepted = true
                    }
                    // If replay detected, early data is rejected but handshake continues with 1-RTT
                }
            }

            // Generate server key share and perform key agreement adapter-side.
            // KEM-based hybrid groups (X25519MLKEM768) require encapsulation against
            // the client's share and have no place in the DH-only seam, so share
            // generation and agreement happen here; the resolved shared secret is
            // handed to the core as `.precomputed` (byte-identical).
            let (ourShare, sharedSecret) = try KeyExchange.respond(
                group: selectedGroup,
                peerShare: Data(peerKeyShareEntry.keyExchange)
            )
            state.context.sharedSecret = sharedSecret

            // Negotiate ALPN (RFC 7301 Section 3.2, RFC 8446 Section 4.2.7)
            if let clientALPN = clientHello.alpn {
                if !configuration.alpnProtocols.isEmpty {
                    guard let common = ALPNExtension(protocols: configuration.alpnProtocols)
                        .negotiate(with: clientALPN) else {
                        throw TLSHandshakeError.noALPNMatch
                    }
                    state.context.negotiatedALPN = common
                }
                // RFC 7301: Server SHOULD NOT respond with ALPN if it has no configured list.
                // negotiatedALPN stays nil, so EncryptedExtensions won't include ALPN.
            } else if !configuration.alpnProtocols.isEmpty {
                throw TLSHandshakeError.noALPNMatch
            }

            // Negotiate certificate types (RFC 7250).
            // PSK handshakes carry no Certificate messages, so the
            // extensions are not negotiated or echoed.
            let willRequestClientCertificate =
                !state.context.pskUsed && configuration.requireClientCertificate
            var echoServerCertificateType = false
            var echoClientCertificateType = false

            if !state.context.pskUsed {
                if let offeredTypes = clientHello.serverCertificateTypes {
                    // Server preference order over the client's offer
                    guard let selected = configuration.localCertificateTypes
                        .first(where: { offeredTypes.contains($0) }) else {
                        throw TLSHandshakeError.unsupportedCertificateType(
                            "No common server certificate type"
                        )
                    }
                    state.context.negotiatedServerCertificateType = selected
                    echoServerCertificateType = true
                } else if !configuration.localCertificateTypes.contains(.x509) {
                    // We can only present a raw public key but the client
                    // did not offer to accept one.
                    throw TLSHandshakeError.unsupportedCertificateType(
                        "Client did not offer raw_public_key for the server certificate"
                    )
                }

                if willRequestClientCertificate {
                    if let offeredTypes = clientHello.clientCertificateTypes {
                        guard let selected = configuration.peerCertificateTypes
                            .first(where: { offeredTypes.contains($0) }) else {
                            throw TLSHandshakeError.unsupportedCertificateType(
                                "No common client certificate type"
                            )
                        }
                        state.context.negotiatedClientCertificateType = selected
                        echoClientCertificateType = true
                    } else if !configuration.peerCertificateTypes.contains(.x509) {
                        // We can only accept a raw public key client
                        // certificate but the client did not offer one.
                        throw TLSHandshakeError.unsupportedCertificateType(
                            "Client did not offer raw_public_key for the client certificate"
                        )
                    }
                }
            }

            var messages: [(Data, TLSEncryptionLevel)] = []
            var outputs: [TLSOutput] = []

            // The negotiated cipher suite for packet protection.
            let cipherSuite = state.context.cipherSuite ?? .tls_aes_128_gcm_sha256

            // Build ServerHello extensions
            var serverHelloExtensions: [TLSExtension] = [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShareServer(KeyShareEntry(group: selectedGroup, keyExchange: ourShare))
            ]

            // Add pre_shared_key extension if PSK was accepted
            if let pskIndex = selectedPskIndex {
                serverHelloExtensions.append(.preSharedKeyServer(selectedIdentity: pskIndex))
            }

            // Generate ServerHello (transcript folding is owned by the core)
            let serverHello = try ServerHello(
                legacySessionIDEcho: Data(clientHello.legacySessionID),
                cipherSuite: cipherSuite,
                extensions: serverHelloExtensions
            )
            let serverHelloMessage = serverHello.encodeAsHandshake()

            // Generate EncryptedExtensions
            var eeExtensions: [TLSExtension] = []
            if let alpn = state.context.negotiatedALPN {
                eeExtensions.append(.alpn(ALPNExtension(protocols: [alpn])))
            }
            if let params = transportParameters, !params.isEmpty {
                eeExtensions.append(.transportParameters(params))
            }
            // Echo negotiated certificate types (RFC 7250 Section 2)
            if echoServerCertificateType {
                eeExtensions.append(
                    .serverCertificateTypeSelected(state.context.negotiatedServerCertificateType)
                )
            }
            if echoClientCertificateType {
                eeExtensions.append(
                    .clientCertificateTypeSelected(state.context.negotiatedClientCertificateType)
                )
            }
            // Add early_data extension if we accepted it (RFC 8446 Section 4.2.10)
            if earlyDataAccepted {
                eeExtensions.append(.earlyData(.encryptedExtensions))
            }
            let encryptedExtensions = EncryptedExtensions(extensions: eeExtensions)
            let eeMessage = encryptedExtensions.encodeAsHandshake()

            // CertificateRequest if mutual TLS is required (RFC 8446 Section 4.3.2)
            var certRequestMessage: Data?
            var certificateRequestSignatureAlgorithms: [SignatureScheme]?
            if willRequestClientCertificate {
                let certRequest = CertificateRequest.withDefaultSignatureAlgorithms()
                certRequestMessage = certRequest.encodeAsHandshake()

                // Store the context we sent so we can verify the client echoes it back
                state.context.certificateRequestContext = Data(certRequest.certificateRequestContext)
                // Store the signature algorithms we offered so we can validate the
                // client's CertificateVerify uses one of them (RFC 8446 Section 4.4.3)
                state.context.sentSignatureAlgorithms = certRequest.signatureAlgorithms
                certificateRequestSignatureAlgorithms = certRequest.signatureAlgorithms
                // Remember we requested client certificate
                state.context.expectingClientCertificate = true
            }

            // Generate Certificate for non-PSK handshakes
            // RFC 8446 Section 4.4.2: Server MUST send Certificate in non-PSK handshakes
            var serverCertMessage: Data?
            var serverSigningKey: (any TLSSigningKey)?
            if !state.context.pskUsed {
                guard let signingKey = self.configuration.signingKey else {
                    throw TLSHandshakeError.certificateRequired
                }
                serverSigningKey = signingKey

                // Build the certificate payload from the negotiated type.
                // Raw Public Key (RFC 7250) needs only the signing key;
                // X.509 needs the configured certificate chain.
                let serverCertificates: [Data]
                switch state.context.negotiatedServerCertificateType {
                case .rawPublicKey:
                    serverCertificates = [try SubjectPublicKeyInfo.encode(signingKey: signingKey)]
                case .x509:
                    guard let certChain = self.configuration.certificateChain,
                          !certChain.isEmpty else {
                        throw TLSHandshakeError.certificateRequired
                    }
                    serverCertificates = certChain
                }

                let certificate = Certificate(certificates: serverCertificates)
                serverCertMessage = certificate.encodeAsHandshake()

                // RFC 8446 Section 4.4.3: Server's CertificateVerify scheme must be
                // one of the algorithms offered by the client in signature_algorithms.
                if let clientOffered = state.context.peerSignatureAlgorithms {
                    guard clientOffered.contains(signingKey.scheme) else {
                        throw TLSHandshakeError.signatureVerificationFailed
                    }
                }
            }

            // Drive the Embedded-clean server core: it folds CH (+ optional 0-RTT
            // early-secret), SH, EE, CR, Cert into the transcript, derives the
            // handshake secrets, and (non-PSK) returns the transcript hash to sign
            // the CertificateVerify over with the adapter's `any TLSSigningKey`.
            guard var serverMachine = state.serverMachine else {
                throw TLSHandshakeError.internalError("Server FSM not initialized")
            }
            let flightParameters = TLSServerHandshake<TLSFoundationProvider>.FlightParameters(
                cipherSuite: cipherSuite,
                acceptedPSK: acceptedPSK,
                keyExchange: .precomputed([UInt8](sharedSecret.rawRepresentation)),
                earlyDataAccepted: earlyDataAccepted,
                requestClientCertificate: willRequestClientCertificate,
                certificateRequestSignatureAlgorithms: certificateRequestSignatureAlgorithms
            )
            let flightResult: (
                handshakeSecrets: (client: [UInt8], server: [UInt8]),
                clientEarlyTrafficSecret: [UInt8]?,
                certificateVerifyRequest: TLSServerHandshake<TLSFoundationProvider>.ServerCertificateVerifyRequest?
            )
            do {
                flightResult = try serverMachine.beginServerFlight(
                    clientHelloBytes: [UInt8](clientHelloMessage),
                    parameters: flightParameters,
                    serverHelloBytes: [UInt8](serverHelloMessage),
                    encryptedExtensionsBytes: [UInt8](eeMessage),
                    certificateRequestBytes: certRequestMessage.map { [UInt8]($0) },
                    serverCertificateBytes: serverCertMessage.map { [UInt8]($0) }
                )
            } catch {
                state.serverMachine = serverMachine
                throw error
            }

            // Assemble the wire flight in transcript order.
            messages.append((serverHelloMessage, .initial))

            let clientSecret = Self.symmetricKey(flightResult.handshakeSecrets.client)
            let serverSecret = Self.symmetricKey(flightResult.handshakeSecrets.server)
            state.context.clientHandshakeSecret = clientSecret
            state.context.serverHandshakeSecret = serverSecret
            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .handshake,
                clientSecret: clientSecret,
                serverSecret: serverSecret,
                cipherSuite: cipherSuite
            )))

            // 0-RTT keys (after handshake keys, matching the legacy ordering).
            if earlyDataAccepted, let earlySecretBytes = flightResult.clientEarlyTrafficSecret {
                let earlyTrafficSecret = Self.symmetricKey(earlySecretBytes)
                state.context.clientEarlyTrafficSecret = earlyTrafficSecret
                state.context.earlyDataState.clientEarlyTrafficSecret = earlyTrafficSecret
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .earlyData,
                    clientSecret: earlyTrafficSecret,
                    serverSecret: nil,  // Server doesn't send 0-RTT
                    cipherSuite: cipherSuite
                )))
            }

            messages.append((eeMessage, .handshake))
            if let crMessage = certRequestMessage {
                messages.append((crMessage, .handshake))
            }

            // Non-PSK: append Certificate, sign + fold CertificateVerify.
            if let certMessage = serverCertMessage,
               let cvRequest = flightResult.certificateVerifyRequest,
               let signingKey = serverSigningKey {
                messages.append((certMessage, .handshake))

                let signatureContent = CertificateVerify.constructSignatureContent(
                    transcriptHash: Data(cvRequest.transcriptHash),
                    isServer: true
                )
                let signature = try signingKey.sign(signatureContent)
                let certificateVerify = CertificateVerify(
                    algorithm: signingKey.scheme,
                    signature: signature
                )
                let cvMessage = certificateVerify.encodeAsHandshake()
                do {
                    try serverMachine.foldServerCertificateVerify(messageBytes: [UInt8](cvMessage))
                } catch {
                    state.serverMachine = serverMachine
                    throw error
                }
                messages.append((cvMessage, .handshake))
            }

            // Build the server Finished + application/exporter secrets via the core.
            let finishResult: (
                serverFinished: [UInt8],
                applicationSecrets: (client: [UInt8], server: [UInt8]),
                exporterMasterSecret: [UInt8]
            )
            do {
                finishResult = try serverMachine.finishServerFlight()
            } catch {
                state.serverMachine = serverMachine
                throw error
            }
            messages.append((Data(finishResult.serverFinished), .handshake))

            let clientAppSecret = Self.symmetricKey(finishResult.applicationSecrets.client)
            let serverAppSecret = Self.symmetricKey(finishResult.applicationSecrets.server)
            state.context.clientApplicationSecret = clientAppSecret
            state.context.serverApplicationSecret = serverAppSecret
            state.context.exporterMasterSecret = Self.symmetricKey(finishResult.exporterMasterSecret)
            outputs.append(.keysAvailable(KeysAvailableInfo(
                level: .application,
                clientSecret: clientAppSecret,
                serverSecret: serverAppSecret,
                cipherSuite: cipherSuite
            )))

            // Sync the adapter key schedule to the negotiated suite so the adapter's
            // hash-length reads (client Finished decode) match the core's hash.
            state.context.keySchedule = TLSKeySchedule(cipherSuite: cipherSuite)
            state.serverMachine = serverMachine

            // Transition state - wait for client certificate if we requested it
            if state.context.expectingClientCertificate {
                state.handshakeState = .waitClientCertificate
            } else {
                state.handshakeState = .waitFinished
            }

            return (ClientHelloResponse(messages: messages), outputs)
        }
    }

    /// Send HelloRetryRequest when client's key_share doesn't contain a supported group
    /// RFC 8446 Section 4.1.4
    private func sendHelloRetryRequest(
        clientHello: ClientHello,
        clientHelloData: Data,
        requestedGroup: NamedGroup,
        state: inout ServerState
    ) throws -> (response: ClientHelloResponse, outputs: [TLSOutput]) {
        // Prevent multiple HRRs (RFC 8446: at most one HRR per connection)
        guard !state.context.sentHelloRetryRequest else {
            throw TLSHandshakeError.unexpectedMessage("Multiple HelloRetryRequest not allowed")
        }

        // Mark that we're sending HRR
        state.context.sentHelloRetryRequest = true
        state.context.helloRetryRequestGroup = requestedGroup

        // The complete ClientHello1 handshake message.
        let clientHelloMessage = HandshakeCodec.encode(type: .clientHello, content: clientHelloData)

        // Use the already-negotiated cipher suite (set in processClientHello)
        let negotiatedSuite = state.context.cipherSuite ?? .tls_aes_128_gcm_sha256

        // Generate HelloRetryRequest
        // HRR is a ServerHello with special random (SHA-256 of "HelloRetryRequest")
        let hrr = try ServerHello.helloRetryRequest(
            legacySessionIDEcho: clientHello.legacySessionID,
            cipherSuite: negotiatedSuite,
            extensions: [
                .supportedVersionsServer(TLSConstants.version13),
                .keyShare(.helloRetryRequest(KeyShareHelloRetryRequest(selectedGroup: requestedGroup)))
            ]
        )
        let hrrMessage = hrr.encodeAsHandshake()

        // RFC 8446 Section 4.4.1: the HRR transcript transform (message_hash(CH1)
        // synthetic message, then HRR) is applied by the Embedded-clean core.
        guard var serverMachine = state.serverMachine else {
            throw TLSHandshakeError.internalError("Server FSM not initialized")
        }
        do {
            try serverMachine.applyHelloRetryRequest(
                cipherSuite: negotiatedSuite,
                clientHello1Bytes: [UInt8](clientHelloMessage),
                helloRetryRequestBytes: [UInt8](hrrMessage)
            )
        } catch {
            state.serverMachine = serverMachine
            throw error
        }
        state.serverMachine = serverMachine

        // Transition state to wait for ClientHello2
        state.handshakeState = .sentHelloRetryRequest

        return (
            ClientHelloResponse(messages: [(hrrMessage, .initial)]),
            []  // No keys available yet, handshake continues after ClientHello2
        )
    }

    /// Process EndOfEarlyData message from client (RFC 8446 Section 4.5)
    ///
    /// This message indicates the client has finished sending 0-RTT data.
    /// It is encrypted under the client_early_traffic_secret (0-RTT keys).
    ///
    /// Returns `.earlyDataEnd` to signal TLSConnection to discard the
    /// earlyDataCryptor and resume using the main cryptor (handshake keys)
    /// for subsequent records (client Finished).
    public func processEndOfEarlyData(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            // EndOfEarlyData is only valid if we accepted early data
            guard state.context.earlyDataState.earlyDataAccepted else {
                throw TLSHandshakeError.unexpectedMessage(
                    "EndOfEarlyData received but early data was not accepted"
                )
            }

            // Validate the message (must be empty)
            let _ = try EndOfEarlyData.decode(from: data)

            // Fold EndOfEarlyData into the transcript via the core.
            let message = HandshakeCodec.encode(type: .endOfEarlyData, content: data)
            guard var serverMachine = state.serverMachine else {
                throw TLSHandshakeError.internalError("Server FSM not initialized")
            }
            do {
                try serverMachine.ingestEndOfEarlyData(rawMessageBytes: [UInt8](message))
            } catch {
                state.serverMachine = serverMachine
                throw error
            }
            state.serverMachine = serverMachine

            // Mark early data as no longer active
            state.context.earlyDataState.attemptingEarlyData = false

            // Signal TLSConnection to discard the earlyDataCryptor.
            // After this, server decrypts with handshake receive keys (main cryptor).
            return [.earlyDataEnd]
        }
    }

    /// Process client Certificate message (for mutual TLS)
    ///
    /// RFC 8446 Section 4.4.2: Client sends Certificate in response to CertificateRequest.
    /// The certificate_request_context MUST match what was sent in CertificateRequest.
    public func processClientCertificate(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitClientCertificate else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client Certificate")
            }

            let certificate = try Certificate.decode(from: data)

            // RFC 8446 Section 4.4.2: certificate_request_context MUST match
            // the context sent in CertificateRequest
            guard certificate.certificateRequestContext == state.context.certificateRequestContext else {
                throw TLSHandshakeError.invalidExtension(
                    "certificate_request_context mismatch in client Certificate"
                )
            }

            guard var serverMachine = state.serverMachine else {
                throw TLSHandshakeError.internalError("Server FSM not initialized")
            }
            let message = HandshakeCodec.encode(type: .certificate, content: data)

            // Check if client sent any certificates
            guard !certificate.certificates.isEmpty else {
                // Client sent empty certificate - fail if we require client auth
                if configuration.requireClientCertificate {
                    throw TLSHandshakeError.certificateRequired
                }
                // No client cert: fold the (empty) Certificate and skip to Finished.
                do {
                    _ = try serverMachine.ingestClientCertificate(
                        certificatePresented: false,
                        rawMessageBytes: [UInt8](message)
                    )
                } catch {
                    state.serverMachine = serverMachine
                    throw error
                }
                state.serverMachine = serverMachine
                state.handshakeState = .waitFinished
                return []
            }

            // Store client certificates
            state.context.clientCertificates = certificate.certificatesData

            // --- Adapter-side: parse + trust-evaluate the client certificate. ---
            switch state.context.negotiatedClientCertificateType {
            case .rawPublicKey:
                // Raw Public Key path (RFC 7250): the single certificate
                // entry is a DER SubjectPublicKeyInfo. Trust is evaluated
                // here; CertificateVerify proves possession of the key.
                let spki = try RawPublicKeyValidator.validate(
                    certificate: certificate,
                    configuration: configuration
                )
                state.context.clientVerificationKey = spki.verificationKey

            case .x509:
                // Parse leaf certificate for verification
                guard let leafCertData = certificate.certificatesData.first else {
                    throw TLSHandshakeError.certificateVerificationFailed("No leaf certificate")
                }

                let leafCert = try X509Certificate.parse(from: leafCertData)
                state.context.clientCertificate = leafCert

                // Extract verification key from certificate
                state.context.clientVerificationKey = try leafCert.extractPublicKey()
            }

            // --- Core: fold the Certificate into the transcript, transition. ---
            do {
                _ = try serverMachine.ingestClientCertificate(
                    certificatePresented: true,
                    rawMessageBytes: [UInt8](message)
                )
            } catch {
                state.serverMachine = serverMachine
                throw error
            }
            state.serverMachine = serverMachine

            // Transition to wait for CertificateVerify
            state.handshakeState = .waitClientCertificateVerify

            return []
        }
    }

    /// Process client CertificateVerify message (for mutual TLS)
    ///
    /// RFC 8446 Section 4.4.3: Verifies client's signature over the transcript.
    /// The signature context is "TLS 1.3, client CertificateVerify".
    public func processClientCertificateVerify(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitClientCertificateVerify else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client CertificateVerify")
            }

            let certificateVerify = try CertificateVerify.decode(from: data)

            // Resolve the client public key adapter-side (the key the X.509 / RPK
            // layer extracted from the client Certificate). The core performs the
            // proof-of-possession signature check (fail-closed) through the seam
            // verifier, enforces the offered-algorithm + scheme-match rules, and
            // folds the CertificateVerify into the transcript.
            let clientPublicKey: (bytes: [UInt8], scheme: SignatureScheme)?
            if let extractedKey = state.context.clientVerificationKey as? VerificationKey {
                clientPublicKey = ([UInt8](extractedKey.publicKeyBytes), extractedKey.scheme)
            } else {
                clientPublicKey = nil
            }

            guard var serverMachine = state.serverMachine else {
                throw TLSHandshakeError.internalError("Server FSM not initialized")
            }
            let message = HandshakeCodec.encode(type: .certificateVerify, content: data)
            do {
                try serverMachine.ingestClientCertificateVerify(
                    certificateVerify,
                    clientPublicKey: clientPublicKey,
                    rawMessageBytes: [UInt8](message)
                )
            } catch {
                state.serverMachine = serverMachine
                throw error
            }
            state.serverMachine = serverMachine

            // Perform X.509 chain validation for client certificate (mTLS)
            // Skip if expectedPeerPublicKey is set (raw public key verification mode)
            // or if Raw Public Key was negotiated (trust evaluated at Certificate time)
            if configuration.verifyPeer && configuration.expectedPeerPublicKey == nil
                && state.context.negotiatedClientCertificateType == .x509 {
                guard let leafCert = state.context.clientCertificate else {
                    throw TLSHandshakeError.certificateVerificationFailed("Missing client certificate")
                }

                // Parse intermediate certificates
                let intermediateCerts = try (state.context.clientCertificates ?? []).dropFirst().compactMap { certData -> X509Certificate? in
                    try X509Certificate.parse(from: certData)
                }

                // Set up validation options for client certificates
                var validationOptions = X509ValidationOptions()
                validationOptions.allowSelfSigned = configuration.allowSelfSigned
                validationOptions.revocationCheckMode = configuration.revocationCheckMode
                // RFC 5280 Section 4.2.1.12: Client certificates MUST have clientAuth EKU
                validationOptions.requiredEKU = .clientAuth
                // No hostname validation for client certificates

                let x509Validator = X509Validator(
                    trustedRoots: configuration.trustedRootCertificates ?? [],
                    options: validationOptions
                )

                do {
                    try x509Validator.validate(certificate: leafCert, intermediates: Array(intermediateCerts))
                } catch let error as X509Error {
                    throw TLSHandshakeError.certificateVerificationFailed(error.description)
                }
            }

            // Call custom certificate validator if configured
            if let validator = configuration.certificateValidator,
               let clientCerts = state.context.clientCertificates {
                let peerInfo = try validator(clientCerts)
                state.context.validatedPeerInfo = peerInfo
            }

            // Transition to wait for Finished
            state.handshakeState = .waitFinished

            return []
        }
    }

    /// Process client Finished message
    public func processClientFinished(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitFinished else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected client Finished")
            }

            let clientFinished = try Finished.decode(from: data, hashLength: state.context.keySchedule.hashLength)

            guard var serverMachine = state.serverMachine else {
                throw TLSHandshakeError.internalError("Server FSM not initialized")
            }

            // --- Core: verify the client Finished MAC (fail-closed), fold it into
            // the transcript, and derive the resumption master secret. ---
            do {
                try serverMachine.ingestClientFinished(clientFinished)
            } catch {
                state.serverMachine = serverMachine
                throw error
            }

            // Capture the resumption secret + restore the key schedule (advanced to
            // the master-secret state) so generateNewSessionTicket can derive ticket
            // PSKs. The transcript is no longer needed post-handshake.
            state.context.resumptionMasterSecret =
                serverMachine.resumptionMasterSecret.map(Self.symmetricKey)
            state.context.keySchedule.coreValue = serverMachine.currentKeySchedule
            state.serverMachine = serverMachine

            // Transition state
            state.handshakeState = .connected

            // Clear handshake-phase secrets no longer needed
            state.context.zeroizeSecrets()

            return [
                .handshakeComplete(HandshakeCompleteInfo(
                    alpn: state.context.negotiatedALPN,
                    zeroRTTAccepted: state.context.earlyDataState.earlyDataAccepted,
                    resumptionTicket: nil
                ))
            ]
        }
    }

    /// Generate a NewSessionTicket for the client
    /// Call this after handshake completion to enable session resumption
    public func generateNewSessionTicket(
        maxEarlyDataSize: UInt32 = 0,
        lifetime: UInt32 = 86400
    ) throws -> (ticket: NewSessionTicket, data: Data) {
        return try state.withLock { state in
            guard state.handshakeState == .connected else {
                throw TLSHandshakeError.internalError("Cannot generate ticket before handshake completion")
            }

            guard let store = sessionTicketStore else {
                throw TLSHandshakeError.internalError("No session ticket store configured")
            }

            guard let resumptionMasterSecret = state.context.resumptionMasterSecret else {
                throw TLSHandshakeError.internalError("Missing resumption master secret")
            }

            // Generate random ticket_age_add
            let ticketAgeAddBytes = try secureRandomBytes(count: 4)
            let ticketAgeAdd = ticketAgeAddBytes.withUnsafeBytes { $0.load(as: UInt32.self) }

            // Create stored session
            let session = SessionTicketStore.StoredSession(
                resumptionMasterSecret: resumptionMasterSecret,
                cipherSuite: state.context.cipherSuite ?? .tls_aes_128_gcm_sha256,
                lifetime: lifetime,
                ticketAgeAdd: ticketAgeAdd,
                alpn: state.context.negotiatedALPN,
                maxEarlyDataSize: maxEarlyDataSize
            )

            // Generate ticket through store
            let ticket = try store.generateTicket(for: session)

            // Encode as handshake message
            let ticketData = ticket.encodeMessage()

            return (ticket, ticketData)
        }
    }

    /// Negotiated ALPN protocol
    public var negotiatedALPN: String? {
        state.withLock { $0.context.negotiatedALPN }
    }

    /// Peer transport parameters
    public var peerTransportParameters: Data? {
        state.withLock { $0.context.peerTransportParameters }
    }

    /// Whether handshake is complete
    public var isConnected: Bool {
        state.withLock { $0.handshakeState == .connected }
    }

    /// Exporter master secret (available after handshake completion)
    public var exporterMasterSecret: SymmetricKey? {
        state.withLock { $0.context.exporterMasterSecret }
    }

    /// Whether PSK was used for authentication
    public var pskUsed: Bool {
        state.withLock { $0.context.pskUsed }
    }

    /// Resumption master secret (available after handshake completion)
    public var resumptionMasterSecret: SymmetricKey? {
        state.withLock { $0.context.resumptionMasterSecret }
    }

    /// Peer certificates (raw DER data, leaf certificate first)
    public var peerCertificates: [Data]? {
        state.withLock { $0.context.peerCertificates }
    }

    /// Validated peer info from certificate validator callback.
    ///
    /// This contains the value returned by `TLSConfiguration.certificateValidator`
    /// after successful certificate validation (e.g., PeerID for libp2p).
    public var validatedPeerInfo: (any Sendable)? {
        state.withLock { $0.context.validatedPeerInfo }
    }

    /// Client certificates received from peer (server-side, for mTLS).
    public var clientCertificates: [Data]? {
        state.withLock { $0.context.clientCertificates }
    }

    /// Parsed client leaf certificate (server-side, for mTLS).
    public var clientCertificate: X509Certificate? {
        state.withLock { $0.context.clientCertificate }
    }

    /// Parsed peer leaf certificate
    public var peerCertificate: X509Certificate? {
        state.withLock { $0.context.peerCertificate }
    }
}

// MARK: - Cipher Suite Extension

extension CipherSuite {
    /// Computes transcript hash using the appropriate hash algorithm for this cipher suite
    ///
    /// RFC 8446 Section 4.4.1: The Hash function used for transcript hashing
    /// is the one associated with the cipher suite.
    /// - AES-128-GCM-SHA256, ChaCha20-Poly1305-SHA256: SHA-256
    /// - AES-256-GCM-SHA384: SHA-384
    func transcriptHash(of data: Data) -> Data {
        switch self {
        case .tls_aes_256_gcm_sha384:
            return Data(SHA384.hash(data: data))
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256:
            return Data(SHA256.hash(data: data))
        }
    }
}
