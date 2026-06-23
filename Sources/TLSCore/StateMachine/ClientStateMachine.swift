/// TLS 1.3 Client State Machine
///
/// Implements the client-side TLS 1.3 handshake.

import Foundation
import Crypto
import Synchronization
import TLSWireCore
import TLSCryptoCore
import TLSHandshakeCore

// MARK: - Client State Machine

/// Client-side TLS 1.3 state machine.
///
/// This `final class` is the Foundation/I-O adapter: it owns the `Mutex`, parses
/// `Data` ↔ wire types, runs X.509 / raw-public-key trust evaluation, and drives
/// the Embedded-clean post-ServerHello authentication FSM
/// (`TLSHandshakeCore.TLSClientAuthMachine`) under its lock. ClientHello
/// generation, ServerHello processing (key exchange + handshake-secret
/// derivation), HelloRetryRequest, and PSK-binder computation remain adapter-side;
/// from EncryptedExtensions onward the FSM core owns the transcript, key schedule,
/// CertificateVerify proof-of-possession check, Finished MAC, and secret
/// derivation.
public final class ClientStateMachine: Sendable {

    private let state = Mutex<ClientState>(ClientState())

    private struct ClientState: Sendable {
        var handshakeState: ClientHandshakeState = .start
        var context: HandshakeContext = HandshakeContext()
        var configuration: TLSConfiguration = TLSConfiguration()

        /// The Embedded-clean pre-ServerHello FSM: owns the transcript + key
        /// schedule from ClientHello through ServerHello (ClientHello assembly +
        /// PSK binder, HelloRetryRequest, downgrade-sentinel detection, (EC)DHE +
        /// handshake-secret derivation). Handed off to `authMachine` after
        /// ServerHello via `makeAuthMachine`.
        var preMachine: TLSClientHandshake<TLSFoundationProvider>?

        /// The Embedded-clean authentication FSM, constructed at the end of
        /// ServerHello processing and driven from EncryptedExtensions onward.
        var authMachine: TLSClientAuthMachine<TLSFoundationProvider>?
    }

    /// Signature schemes the client advertises. This list is the single source of
    /// truth and MUST match what `VerificationKey` can actually verify — we never
    /// advertise a capability we cannot honor. RSA-PSS schemes are intentionally
    /// excluded because no RSA verifier is implemented; advertising them would let a
    /// server pick an algorithm whose CertificateVerify we could not check, which
    /// would fail the handshake (or, worse, invite an unverifiable peer).
    static let advertisedSignatureSchemes: [SignatureScheme] = [
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .ed25519
    ]

    /// RFC 8446 §4.1.3 downgrade sentinels: the final 8 bytes a server sets in its
    /// ServerHello.random when it negotiated a version below TLS 1.3.
    /// "DOWNGRD" + 0x01 (negotiated TLS 1.2) and "DOWNGRD" + 0x00 (TLS 1.1 or below).
    static let downgradeSentinelTLS12: [UInt8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
    static let downgradeSentinelTLS11OrBelow: [UInt8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

    /// Whether the given 32-byte random ends with a TLS downgrade sentinel.
    static func hasDowngradeSentinel(_ random: Data) -> Bool {
        guard random.count >= 8 else { return false }
        let tail = Array(random.suffix(8))
        return tail == downgradeSentinelTLS12 || tail == downgradeSentinelTLS11OrBelow
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

    // MARK: - Initialization

    public init() {}

    // MARK: - Start Handshake

    /// Generate ClientHello and start the handshake
    /// - Parameters:
    ///   - configuration: TLS configuration
    ///   - transportParameters: Optional transport parameters to send (e.g., for QUIC)
    ///   - sessionTicket: Optional session ticket for resumption
    ///   - attemptEarlyData: Whether to attempt 0-RTT early data
    /// - Returns: The ClientHello message and any TLS outputs
    public func startHandshake(
        configuration: TLSConfiguration,
        transportParameters: Data? = nil,
        sessionTicket: SessionTicketData? = nil,
        attemptEarlyData: Bool = false
    ) throws -> (clientHello: Data, outputs: [TLSOutput]) {
        return try state.withLock { state in
            guard state.handshakeState == .start else {
                throw TLSHandshakeError.unexpectedMessage("Handshake already started")
            }

            state.configuration = configuration
            state.context.localTransportParameters = transportParameters
            state.context.sessionTicket = sessionTicket

            // Generate ephemeral key for key exchange (use first configured group)
            guard let preferredGroup = configuration.supportedGroups.first else {
                throw TLSHandshakeError.noKeyShareMatch
            }
            let keyExchange = try KeyExchange.generate(for: preferredGroup)
            state.context.keyExchange = keyExchange

            // Generate random
            let random = try secureRandomBytes(count: TLSConstants.randomLength)
            state.context.clientRandom = random

            // Session ID for TLS 1.3
            // Using empty session ID for broader interoperability.
            let sessionID = Data()
            state.context.sessionID = sessionID

            // Build extensions
            var extensions: [TLSExtension] = []

            // supported_versions (required for TLS 1.3)
            extensions.append(.supportedVersionsClient([TLSConstants.version13]))

            // supported_groups (from configuration)
            extensions.append(.supportedGroupsList(configuration.supportedGroups))

            // signature_algorithms — only schemes we can actually verify (no RSA).
            extensions.append(.signatureAlgorithmsList(Self.advertisedSignatureSchemes))

            // key_share
            extensions.append(.keyShareClient([keyExchange.keyShareEntry()]))

            // ALPN
            if !configuration.alpnProtocols.isEmpty {
                extensions.append(.alpnProtocols(configuration.alpnProtocols))
            }

            // Server name (SNI)
            if let serverName = configuration.serverName {
                extensions.append(.serverName(ServerNameExtension(hostName: serverName)))
            }

            // Transport parameters (optional, e.g., for QUIC)
            if let params = transportParameters, !params.isEmpty {
                extensions.append(.transportParameters(params))
            }

            // Raw Public Key certificate types (RFC 7250).
            // Only offered when configured beyond the X.509 default.
            if configuration.localCertificateTypes != [.x509] {
                extensions.append(.clientCertificateTypes(configuration.localCertificateTypes))
            }
            if configuration.peerCertificateTypes != [.x509] {
                extensions.append(.serverCertificateTypes(configuration.peerCertificateTypes))
            }

            // Build the cipher suites list (from configuration)
            var cipherSuites: [CipherSuite] = configuration.supportedCipherSuites

            // PSK-related extensions (if we have a session ticket)
            var offeredPsks: OfferedPsks?
            var pskBinder: TLSClientHandshake<TLSFoundationProvider>.PSKBinderInput?

            // The main transcript suite. Kept at the default (SHA-256) to match the
            // legacy adapter's default `TranscriptHash()`; the PSK binder uses its
            // own ticket-suite hash via `PSKBinderInput.binderCipherSuite`.
            let preCipherSuite: CipherSuite = .tls_aes_128_gcm_sha256

            if let ticket = sessionTicket, ticket.isValid() {
                // If resuming, prefer the original cipher suite
                cipherSuites = [ticket.cipherSuite, .tls_aes_128_gcm_sha256]

                // psk_key_exchange_modes (required when offering PSKs)
                // TLS 1.3 requires psk_dhe_ke mode
                extensions.append(.pskKeyExchangeModesList([.psk_dhe_ke]))

                // early_data (if attempting 0-RTT)
                // Sanity check: limit max early data to 16MB to prevent memory issues
                // from maliciously large values
                let maxAllowedEarlyData: UInt32 = 16 * 1024 * 1024  // 16 MB
                let effectiveMaxEarlyData = min(ticket.maxEarlyDataSize, maxAllowedEarlyData)

                if attemptEarlyData && effectiveMaxEarlyData > 0 {
                    extensions.append(.earlyDataClient())
                    state.context.earlyDataState.attemptingEarlyData = true
                    state.context.earlyDataState.maxEarlyDataSize = effectiveMaxEarlyData
                }

                // pre_shared_key must be the last extension
                // Create the PSK identity from the ticket
                let pskIdentity = PskIdentity(ticket: ticket)
                offeredPsks = OfferedPsks(
                    identities: [pskIdentity],
                    binders: [Data(repeating: 0, count: ticket.cipherSuite.hashLength)] // Placeholder
                )
                pskBinder = TLSClientHandshake<TLSFoundationProvider>.PSKBinderInput(
                    psk: Self.secretBytes(ticket.resumptionPSK),
                    isResumption: true,
                    binderCipherSuite: ticket.cipherSuite
                )

                // Store the PSK cipher suite for 0-RTT key output
                // (will be updated to negotiated suite after ServerHello)
                state.context.cipherSuite = ticket.cipherSuite
            }

            // Drive the Embedded-clean pre-ServerHello core: it owns the transcript
            // + key schedule, computes the PSK binder (two-pass, byte-identical),
            // folds ClientHello into the transcript, and derives the 0-RTT secret.
            var preMachine = TLSClientHandshake<TLSFoundationProvider>(
                cipherSuite: preCipherSuite,
                pskOffered: offeredPsks != nil
            )
            let clientHelloBytes: [UInt8]
            let earlyTrafficSecretBytes: [UInt8]?
            (clientHelloBytes, earlyTrafficSecretBytes) = try preMachine.produceClientHello(
                random: [UInt8](random),
                legacySessionID: [UInt8](sessionID),
                cipherSuites: cipherSuites,
                extensions: extensions,
                offeredPsks: offeredPsks,
                pskBinder: pskBinder,
                attemptEarlyData: state.context.earlyDataState.attemptingEarlyData
            )
            let clientHelloMessage = Data(clientHelloBytes)
            if let earlyTrafficSecretBytes {
                state.context.clientEarlyTrafficSecret = Self.symmetricKey(earlyTrafficSecretBytes)
            }
            state.preMachine = preMachine

            // Store offered cipher suites for ServerHello validation
            state.context.offeredCipherSuites = cipherSuites

            // Transition state
            state.handshakeState = .waitServerHello

            // Prepare outputs
            var outputs: [TLSOutput] = []

            // If attempting early data, provide the early keys (0-RTT)
            if let earlySecret = state.context.clientEarlyTrafficSecret,
               let cipherSuite = state.context.cipherSuite {
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: .earlyData,
                    clientSecret: earlySecret,
                    serverSecret: nil, // 0-RTT is client-to-server only
                    cipherSuite: cipherSuite
                )))
            }

            return (clientHelloMessage, outputs)
        }
    }

    // MARK: - Process ServerHello

    /// Process a ServerHello message
    /// - Parameter data: The ServerHello message content (without handshake header)
    /// - Returns: TLS outputs (keys available, etc.)
    public func processServerHello(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            // Accept ServerHello in waitServerHello or waitServerHelloRetry states
            guard state.handshakeState == .waitServerHello ||
                  state.handshakeState == .waitServerHelloRetry else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected ServerHello in state \(state.handshakeState)")
            }

            let serverHello = try ServerHello.decode(from: data)

            // Check for HelloRetryRequest
            if serverHello.isHelloRetryRequest {
                return try processHelloRetryRequest(serverHello, data: data, state: &state)
            }

            // Verify supported_versions extension
            guard let supportedVersions = serverHello.supportedVersions,
                  supportedVersions.isTLS13 else {
                throw TLSHandshakeError.unsupportedVersion
            }

            // RFC 8446 §4.1.3: downgrade protection. A genuine TLS 1.3 server sets
            // the last 8 bytes of its random to a sentinel ONLY when it negotiated a
            // lower version. Since we negotiate TLS 1.3, observing either sentinel
            // here means an attacker forced a downgrade — abort the handshake.
            if Self.hasDowngradeSentinel(Data(serverHello.random)) {
                throw TLSHandshakeError.downgradeDetected
            }

            // Validate legacy_session_id_echo (must match what we sent)
            guard serverHello.legacySessionIDEcho == state.context.sessionID else {
                throw TLSHandshakeError.invalidExtension("ServerHello legacy_session_id_echo does not match ClientHello")
            }

            // Validate cipher suite (must be one we offered in ClientHello)
            guard state.context.offeredCipherSuites.contains(serverHello.cipherSuite) else {
                throw TLSHandshakeError.noCipherSuiteMatch
            }

            // RFC 8446 Section 4.1.4: After HRR, ServerHello cipher suite
            // MUST match the one selected in HelloRetryRequest.
            if state.context.receivedHelloRetryRequest {
                guard serverHello.cipherSuite == state.context.cipherSuite else {
                    throw TLSHandshakeError.invalidExtension(
                        "ServerHello cipher suite differs from HelloRetryRequest"
                    )
                }
            }

            // Check for PSK acceptance
            var pskAccepted = false
            if let pskExtension = serverHello.extensions.first(where: { $0.extensionType == .preSharedKey }) {
                if case .preSharedKey(.serverHello(let selectedPsk)) = pskExtension {
                    // Verify the selected identity is valid (we only offer 1 PSK, so must be 0)
                    guard selectedPsk.selectedIdentity == 0 else {
                        throw TLSHandshakeError.invalidExtension("Invalid PSK selection: \(selectedPsk.selectedIdentity)")
                    }

                    // RFC 8446 Section 4.2.11: The cipher suite MUST match the PSK's cipher suite
                    // state.context.cipherSuite was set to ticket.cipherSuite when we started with PSK
                    if let pskCipherSuite = state.context.cipherSuite,
                       pskCipherSuite != serverHello.cipherSuite {
                        throw TLSHandshakeError.invalidExtension(
                            "Cipher suite mismatch: PSK uses \(pskCipherSuite), server selected \(serverHello.cipherSuite)"
                        )
                    }

                    pskAccepted = true
                    state.context.pskUsed = true
                    state.context.selectedPskIdentity = selectedPsk.selectedIdentity
                }
            }

            // Get key_share extension (required even for PSK-DHE mode)
            guard let serverKeyShare = serverHello.keyShare else {
                throw TLSHandshakeError.missingExtension("key_share")
            }

            // Verify we have a key for this group
            guard let ourKeyExchange = state.context.keyExchange,
                  ourKeyExchange.group == serverKeyShare.serverShare.group else {
                throw TLSHandshakeError.noKeyShareMatch
            }

            // Perform key agreement adapter-side. Pure-DH groups route through the
            // `TLSKeyExchange` seam; the X25519MLKEM768 hybrid (a KEM with no place
            // in the DH-only seam) is decapsulated here. The resolved shared secret
            // is handed to the core as `.precomputed` so behavior stays
            // byte-identical to the pre-FSM key agreement.
            let sharedSecret = try ourKeyExchange.sharedSecret(with: Data(serverKeyShare.serverShare.keyExchange))
            state.context.sharedSecret = sharedSecret

            // Store cipher suite
            state.context.cipherSuite = serverHello.cipherSuite
            state.context.serverRandom = Data(serverHello.random)

            // Drive the Embedded-clean pre-ServerHello core: it performs the RFC
            // 8446 §4.1.3 downgrade-sentinel check (fail-closed), folds ServerHello
            // into the transcript, reinitialises the key schedule for the negotiated
            // suite when no PSK was accepted, and derives the handshake secrets.
            guard var preMachine = state.preMachine else {
                throw TLSHandshakeError.internalError("Pre-ServerHello FSM not initialized")
            }
            let serverHelloMessage = HandshakeCodec.encode(type: .serverHello, content: data)
            let (clientSecretBytes, serverSecretBytes): ([UInt8], [UInt8])
            do {
                (clientSecretBytes, serverSecretBytes) = try preMachine.ingestServerHello(
                    serverRandom: [UInt8](serverHello.random),
                    cipherSuite: serverHello.cipherSuite,
                    pskAccepted: pskAccepted,
                    keyExchange: .precomputed([UInt8](sharedSecret.rawRepresentation)),
                    rawMessageBytes: [UInt8](serverHelloMessage)
                )
            } catch {
                state.preMachine = preMachine
                throw error
            }
            let clientSecret = Self.symmetricKey(clientSecretBytes)
            let serverSecret = Self.symmetricKey(serverSecretBytes)
            state.context.clientHandshakeSecret = clientSecret
            state.context.serverHandshakeSecret = serverSecret

            // Sync the adapter key schedule to the negotiated cipher suite so the
            // adapter's `hashLength`-dependent reads (server Finished decode) match
            // the core's hash. The core owns the live key schedule; this adapter
            // copy is only used for hash-length and post-handshake ticket PSK
            // derivation (restored from the auth FSM in processServerFinished).
            state.context.keySchedule = TLSKeySchedule(cipherSuite: serverHello.cipherSuite)

            // Hand ownership of the transcript + key schedule to the Embedded-clean
            // authentication FSM. From EncryptedExtensions onward the core owns
            // both; the adapter stops updating them (R1: single transcript owner).
            state.authMachine = try preMachine.makeAuthMachine(
                verifyPeer: state.configuration.verifyPeer
            )
            state.preMachine = nil

            // Transition state
            state.handshakeState = .waitEncryptedExtensions

            // Return keys available output
            return [
                .keysAvailable(KeysAvailableInfo(
                    level: .handshake,
                    clientSecret: clientSecret,
                    serverSecret: serverSecret,
                    cipherSuite: serverHello.cipherSuite
                ))
            ]
        }
    }

    // MARK: - Process HelloRetryRequest

    /// Process a HelloRetryRequest message
    /// - Parameters:
    ///   - hrr: The decoded HelloRetryRequest (ServerHello with special random)
    ///   - data: The raw message data
    ///   - state: The client state (mutable)
    /// - Returns: TLS outputs including the new ClientHello2
    private func processHelloRetryRequest(
        _ hrr: ServerHello,
        data: Data,
        state: inout ClientState
    ) throws -> [TLSOutput] {
        // Ensure we haven't already received an HRR (only one allowed)
        guard !state.context.receivedHelloRetryRequest else {
            throw TLSHandshakeError.unexpectedMessage("Received second HelloRetryRequest")
        }
        state.context.receivedHelloRetryRequest = true

        // RFC 8446 Section 4.2.10: If 0-RTT was attempted, HRR means early data
        // must be abandoned. Server will not accept 0-RTT after HRR.
        state.context.earlyDataState.attemptingEarlyData = false
        state.context.earlyDataState.earlyDataAccepted = false

        // Get the requested group from HRR
        guard let requestedGroup = hrr.helloRetryRequestSelectedGroup else {
            throw TLSHandshakeError.missingExtension("key_share in HelloRetryRequest")
        }

        // Verify we support the requested group (from configuration)
        // RFC 8446 Section 4.1.4: illegal_parameter if group is not supported
        guard state.configuration.supportedGroups.contains(requestedGroup) else {
            throw TLSHandshakeError.invalidExtension(
                "HelloRetryRequest selected unsupported group"
            )
        }

        // Store cipher suite from HRR
        state.context.cipherSuite = hrr.cipherSuite

        // RFC 8446 Section 4.4.1: Special transcript handling for HRR — applied by
        // the Embedded-clean core (message_hash(CH1) synthetic transform, then HRR),
        // which also abandons 0-RTT and fixes the negotiated cipher suite.
        guard var preMachine = state.preMachine else {
            throw TLSHandshakeError.internalError("Pre-ServerHello FSM not initialized")
        }
        let hrrMessage = HandshakeCodec.encode(type: .serverHello, content: data)
        do {
            try preMachine.applyHelloRetryRequest(
                cipherSuite: hrr.cipherSuite,
                rawMessageBytes: [UInt8](hrrMessage)
            )
        } catch {
            state.preMachine = preMachine
            throw error
        }

        // Generate new key pair for the requested group
        let newKeyExchange = try KeyExchange.generate(for: requestedGroup)
        state.context.keyExchange = newKeyExchange

        // Build ClientHello2 with the new key share (the core recomputes the PSK
        // binder over the message_hash + HRR transcript and folds CH2 in).
        let clientHello2 = try generateClientHello2(
            state: &state,
            preMachine: &preMachine,
            keyExchange: newKeyExchange
        )
        state.preMachine = preMachine

        // Transition state
        state.handshakeState = .waitServerHelloRetry

        // Return the new ClientHello
        return [.handshakeData(clientHello2, level: .initial)]
    }

    /// Generate ClientHello2 after HelloRetryRequest
    private func generateClientHello2(
        state: inout ClientState,
        preMachine: inout TLSClientHandshake<TLSFoundationProvider>,
        keyExchange: KeyExchange
    ) throws -> Data {
        // Build extensions (similar to startHandshake but with new key_share)
        var extensions: [TLSExtension] = []

        // supported_versions (required for TLS 1.3)
        extensions.append(.supportedVersionsClient([TLSConstants.version13]))

        // supported_groups (from configuration)
        extensions.append(.supportedGroupsList(state.configuration.supportedGroups))

        // signature_algorithms — only schemes we can actually verify (no RSA).
        extensions.append(.signatureAlgorithmsList(Self.advertisedSignatureSchemes))

        // key_share with the new key
        extensions.append(.keyShareClient([keyExchange.keyShareEntry()]))

        // ALPN
        if !state.configuration.alpnProtocols.isEmpty {
            extensions.append(.alpnProtocols(state.configuration.alpnProtocols))
        }

        // Server name (SNI)
        if let serverName = state.configuration.serverName {
            extensions.append(.serverName(ServerNameExtension(hostName: serverName)))
        }

        // Transport parameters (optional, e.g., for QUIC)
        if let params = state.context.localTransportParameters, !params.isEmpty {
            extensions.append(.transportParameters(params))
        }

        // Raw Public Key certificate types (RFC 7250).
        // Only offered when configured beyond the X.509 default.
        if state.configuration.localCertificateTypes != [.x509] {
            extensions.append(.clientCertificateTypes(state.configuration.localCertificateTypes))
        }
        if state.configuration.peerCertificateTypes != [.x509] {
            extensions.append(.serverCertificateTypes(state.configuration.peerCertificateTypes))
        }

        // Build ClientHello2
        guard let clientRandom = state.context.clientRandom,
              let sessionID = state.context.sessionID else {
            throw TLSHandshakeError.internalError("Missing client random or session ID")
        }

        // PSK extension (must be last if present)
        // If we were doing PSK resumption before HRR, re-add PSK with updated binder
        var offeredPsks: OfferedPsks?
        var pskBinder: TLSClientHandshake<TLSFoundationProvider>.PSKBinderInput?

        if let ticket = state.context.sessionTicket, ticket.isValid(), state.context.pskUsed || preMachine.pskWasOffered {
            // psk_key_exchange_modes (required when offering PSKs)
            extensions.append(.pskKeyExchangeModesList([.psk_dhe_ke]))

            // Create the PSK identity from the ticket
            let pskIdentity = PskIdentity(ticket: ticket)
            offeredPsks = OfferedPsks(
                identities: [pskIdentity],
                binders: [Data(repeating: 0, count: ticket.cipherSuite.hashLength)] // Placeholder
            )
            pskBinder = TLSClientHandshake<TLSFoundationProvider>.PSKBinderInput(
                psk: Self.secretBytes(ticket.resumptionPSK),
                isResumption: true,
                binderCipherSuite: ticket.cipherSuite
            )
        }

        // The Embedded-clean core recomputes the PSK binder over the message_hash +
        // HRR transcript and folds ClientHello2 into the transcript (byte-identical
        // two-pass build).
        let clientHello2Bytes = try preMachine.produceClientHello2(
            random: [UInt8](clientRandom),
            legacySessionID: [UInt8](sessionID),
            cipherSuites: state.context.offeredCipherSuites,
            extensions: extensions,
            offeredPsks: offeredPsks,
            pskBinder: pskBinder
        )

        return Data(clientHello2Bytes)
    }

    // MARK: - Process EncryptedExtensions

    /// Process an EncryptedExtensions message
    /// - Parameter data: The EncryptedExtensions message content
    /// - Returns: TLS outputs
    public func processEncryptedExtensions(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitEncryptedExtensions else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected EncryptedExtensions")
            }

            let encryptedExtensions = try EncryptedExtensions.decode(from: data)

            // Validate ALPN (RFC 7301 Section 3.2)
            if let alpn = encryptedExtensions.selectedALPN {
                // Server MUST NOT send ALPN if client didn't offer any
                guard !state.configuration.alpnProtocols.isEmpty else {
                    throw TLSHandshakeError.invalidExtension("Server sent ALPN but client did not offer any")
                }
                // Server's selection must be one we offered
                guard state.configuration.alpnProtocols.contains(alpn) else {
                    throw TLSHandshakeError.noALPNMatch
                }
                state.context.negotiatedALPN = alpn
            }

            // Extract transport parameters (optional)
            if let params = encryptedExtensions.transportParameters {
                state.context.peerTransportParameters = Data(params)
            }

            // Validate Raw Public Key negotiation (RFC 7250)
            if let selectedType = encryptedExtensions.selectedServerCertificateType {
                guard state.configuration.peerCertificateTypes != [.x509] else {
                    throw TLSHandshakeError.invalidExtension(
                        "Server sent server_certificate_type but client did not offer it"
                    )
                }
                guard state.configuration.peerCertificateTypes.contains(selectedType) else {
                    throw TLSHandshakeError.unsupportedCertificateType(
                        "Server selected a server certificate type the client did not offer"
                    )
                }
                state.context.negotiatedServerCertificateType = selectedType
            } else if !state.context.pskUsed,
                      !state.configuration.peerCertificateTypes.contains(.x509) {
                // We cannot validate X.509 and the server did not agree to
                // send a raw public key.
                throw TLSHandshakeError.unsupportedCertificateType(
                    "Server did not select raw_public_key and X.509 is not enabled"
                )
            }

            if let selectedType = encryptedExtensions.selectedClientCertificateType {
                guard state.configuration.localCertificateTypes != [.x509] else {
                    throw TLSHandshakeError.invalidExtension(
                        "Server sent client_certificate_type but client did not offer it"
                    )
                }
                guard state.configuration.localCertificateTypes.contains(selectedType) else {
                    throw TLSHandshakeError.unsupportedCertificateType(
                        "Server selected a client certificate type the client did not offer"
                    )
                }
                state.context.negotiatedClientCertificateType = selectedType
            }

            // Check for early_data acceptance
            let earlyDataAccepted = encryptedExtensions.extensions.contains {
                $0.extensionType == .earlyData
            }

            // Drive the Embedded-clean FSM: it owns the transcript update, the
            // 0-RTT bookkeeping, and the state transition (skipping the
            // certificate phase for a PSK handshake).
            guard var authMachine = state.authMachine else {
                throw TLSHandshakeError.internalError("Authentication FSM not initialized")
            }
            let message = HandshakeCodec.encode(type: .encryptedExtensions, content: data)
            let actions: [TLSHandshakeAction]
            do {
                actions = try authMachine.ingestEncryptedExtensions(
                    rawMessageBytes: [UInt8](message),
                    earlyDataAccepted: earlyDataAccepted
                )
            } catch {
                state.authMachine = authMachine
                throw error
            }
            // Mirror the resolved 0-RTT acceptance into the adapter context (read
            // by `earlyDataAccepted` accessor and `TLS13Handler`).
            if state.context.earlyDataState.attemptingEarlyData {
                state.context.earlyDataState.earlyDataAccepted = authMachine.earlyDataWasAccepted
            }
            state.authMachine = authMachine

            // Mirror the FSM state into the adapter's handshake-state enum.
            state.handshakeState = state.context.pskUsed
                ? .waitFinished
                : .waitCertificateOrCertificateRequest

            return try translate(actions: actions, state: &state)
        }
    }

    // MARK: - Process CertificateRequest

    /// Process a CertificateRequest message (for mutual TLS)
    ///
    /// RFC 8446 Section 4.3.2: Server requests client authentication.
    /// Client stores the context and will send Certificate + CertificateVerify after receiving Finished.
    /// - Parameter data: The CertificateRequest message content
    /// - Returns: TLS outputs
    public func processCertificateRequest(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            // CertificateRequest comes after EncryptedExtensions, before server's Certificate
            guard state.handshakeState == .waitCertificateOrCertificateRequest else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected CertificateRequest in state \(state.handshakeState)")
            }

            let certRequest = try CertificateRequest.decode(from: data)

            // Mirror request state into the adapter context (read by the client
            // certificate flight + accessors); the FSM owns the transcript update.
            state.context.certificateRequestContext = Data(certRequest.certificateRequestContext)
            state.context.clientCertificateRequested = true
            state.context.peerSignatureAlgorithms = certRequest.signatureAlgorithms

            guard var authMachine = state.authMachine else {
                throw TLSHandshakeError.internalError("Authentication FSM not initialized")
            }
            let message = HandshakeCodec.encode(type: .certificateRequest, content: data)
            let actions: [TLSHandshakeAction]
            do {
                actions = try authMachine.ingestCertificateRequest(
                    certRequest,
                    rawMessageBytes: [UInt8](message)
                )
            } catch {
                state.authMachine = authMachine
                throw error
            }
            state.authMachine = authMachine

            // Continue to wait for server's Certificate
            state.handshakeState = .waitCertificate

            return try translate(actions: actions, state: &state)
        }
    }

    // MARK: - Process Certificate

    /// Process a Certificate message
    /// - Parameter data: The Certificate message content
    /// - Returns: TLS outputs
    public func processCertificate(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            // Accept Certificate from either waiting state
            guard state.handshakeState == .waitCertificate ||
                  state.handshakeState == .waitCertificateOrCertificateRequest else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected Certificate")
            }

            let certificate = try Certificate.decode(from: data)

            // Store raw certificates
            state.context.peerCertificates = certificate.certificatesData

            // --- Adapter-side: parse + trust-evaluate the peer certificate. ---
            // The FSM core never touches X.509/ASN.1; it only learns whether a
            // certificate was presented (for the fail-closed CertificateVerify
            // branch) and receives the resolved peer key at CertificateVerify.
            if state.context.negotiatedServerCertificateType == .rawPublicKey {
                // Raw Public Key path (RFC 7250): the single certificate entry
                // is a DER SubjectPublicKeyInfo, not an X.509 certificate.
                let spki = try RawPublicKeyValidator.validate(
                    certificate: certificate,
                    configuration: state.configuration
                )
                state.context.peerVerificationKey = spki.verificationKey
            } else if state.configuration.expectedPeerPublicKey == nil {
                // X.509 path (not raw public key, no explicitly configured key).
                // Skipped if expectedPeerPublicKey is set (raw key verification).
                guard let leafCertData = certificate.leafCertificateData else {
                    throw TLSHandshakeError.certificateVerificationFailed("No certificate provided")
                }

                // Parse the leaf certificate
                let leafCert: X509Certificate
                do {
                    leafCert = try X509Certificate.parse(from: leafCertData)
                } catch {
                    throw TLSHandshakeError.certificateVerificationFailed("Failed to parse certificate: \(error)")
                }

                // Store the parsed certificate
                state.context.peerCertificate = leafCert

                // Always extract and store the leaf public key. The CertificateVerify
                // proof-of-possession signature MUST be verified against it regardless
                // of `verifyPeer`: `verifyPeer` only controls X.509 chain/trust-anchor
                // validation, never the handshake signature (otherwise a single flag
                // would yield an unauthenticated-but-"complete" channel).
                do {
                    state.context.peerVerificationKey = try leafCert.extractPublicKey()
                } catch {
                    throw TLSHandshakeError.certificateVerificationFailed("Failed to extract public key: \(error)")
                }

                // X.509 chain/trust-anchor validation is gated by verifyPeer.
                if state.configuration.verifyPeer {
                    // Parse intermediate certificates
                    let intermediateCerts = try certificate.certificatesData.dropFirst().compactMap { certData -> X509Certificate? in
                        try X509Certificate.parse(from: certData)
                    }

                    // Set up validation options
                    var validationOptions = X509ValidationOptions()
                    validationOptions.hostname = state.configuration.serverName
                    validationOptions.allowSelfSigned = state.configuration.allowSelfSigned
                    validationOptions.revocationCheckMode = state.configuration.revocationCheckMode
                    // RFC 5280 Section 4.2.1.12: Server certificates MUST have serverAuth EKU
                    validationOptions.requiredEKU = .serverAuth

                    // Create validator with trusted roots
                    let validator = X509Validator(
                        trustedRoots: state.configuration.trustedRootCertificates ?? [],
                        options: validationOptions
                    )

                    // Validate the certificate chain
                    do {
                        try validator.validate(certificate: leafCert, intermediates: Array(intermediateCerts))
                    } catch let error as X509Error {
                        throw TLSHandshakeError.certificateVerificationFailed(error.description)
                    }
                }
            }

            // --- Core: fold the Certificate into the transcript, transition. ---
            guard var authMachine = state.authMachine else {
                throw TLSHandshakeError.internalError("Authentication FSM not initialized")
            }
            let message = HandshakeCodec.encode(type: .certificate, content: data)
            let actions: [TLSHandshakeAction]
            do {
                actions = try authMachine.ingestServerCertificate(
                    certificatePresented: !(state.context.peerCertificates?.isEmpty ?? true),
                    rawMessageBytes: [UInt8](message)
                )
            } catch {
                state.authMachine = authMachine
                throw error
            }
            state.authMachine = authMachine
            state.handshakeState = .waitCertificateVerify

            return try translate(actions: actions, state: &state)
        }
    }

    // MARK: - Process CertificateVerify

    /// Process a CertificateVerify message
    /// - Parameter data: The CertificateVerify message content
    /// - Returns: TLS outputs
    public func processCertificateVerify(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            guard state.handshakeState == .waitCertificateVerify else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected CertificateVerify")
            }

            let certificateVerify = try CertificateVerify.decode(from: data)

            // --- Adapter-side peer-key resolution (reads config precedence). ---
            // `expectedPeerPublicKey` (interpreted with the CertificateVerify
            // algorithm, matching the legacy `VerificationKey(publicKeyBytes:
            // scheme: cv.algorithm)` path) takes priority over the certificate
            // key. The certificate key carries its own intrinsic scheme so the
            // core can enforce the scheme/algorithm match (proof-of-possession).
            let peerPublicKey: (bytes: [UInt8], scheme: SignatureScheme)?
            if let expectedPublicKey = state.configuration.expectedPeerPublicKey {
                peerPublicKey = ([UInt8](expectedPublicKey), certificateVerify.algorithm)
            } else if let extractedKey = state.context.peerVerificationKey as? VerificationKey {
                peerPublicKey = ([UInt8](extractedKey.publicKeyBytes), extractedKey.scheme)
            } else {
                peerPublicKey = nil
            }

            // --- Core: proof-of-possession signature check (fail-closed), then
            // fold CertificateVerify into the transcript and request the
            // adapter's certificate validator. ---
            guard var authMachine = state.authMachine else {
                throw TLSHandshakeError.internalError("Authentication FSM not initialized")
            }
            let message = HandshakeCodec.encode(type: .certificateVerify, content: data)
            let actions: [TLSHandshakeAction]
            do {
                actions = try authMachine.ingestServerCertificateVerify(
                    certificateVerify,
                    peerPublicKey: peerPublicKey,
                    rawMessageBytes: [UInt8](message)
                )
            } catch {
                state.authMachine = authMachine
                throw error
            }
            state.authMachine = authMachine

            // Transition state
            state.handshakeState = .waitFinished

            return try translate(actions: actions, state: &state)
        }
    }

    // MARK: - Process Finished

    /// Process a server Finished message
    /// - Parameter data: The Finished message content
    /// - Returns: TLS outputs including EndOfEarlyData (at earlyData level),
    ///   client handshake flight (at handshake level), application keys,
    ///   and handshake complete signal — all in correct order.
    public func processServerFinished(_ data: Data) throws -> [TLSOutput] {
        return try state.withLock { state in
            // Only accept Finished in waitFinished state.
            // PSK mode transitions directly from waitEncryptedExtensions to waitFinished.
            // Non-PSK mode must complete Certificate → CertificateVerify → waitFinished.
            guard state.handshakeState == .waitFinished else {
                throw TLSHandshakeError.unexpectedMessage("Unexpected Finished in state \(state.handshakeState)")
            }

            guard var authMachine = state.authMachine else {
                throw TLSHandshakeError.internalError("Authentication FSM not initialized")
            }

            let serverFinished = try Finished.decode(from: data, hashLength: state.context.keySchedule.hashLength)

            // --- Core: verify the server Finished MAC, derive app/exporter
            // secrets, and emit any EndOfEarlyData / earlyDataEnd actions. ---
            var outputs: [TLSOutput] = []
            do {
                let eoedActions = try authMachine.ingestServerFinished(serverFinished)
                outputs.append(contentsOf: try translate(actions: eoedActions, state: &state))
            } catch {
                state.authMachine = authMachine
                throw error
            }

            // --- Client mTLS flight: signing stays adapter-side so any
            // `any TLSSigningKey` conformer is supported; the core owns the
            // transcript and accumulates the flight bytes. ---
            if state.context.clientCertificateRequested {
                do {
                    try buildClientCertificateFlight(authMachine: &authMachine, state: &state)
                } catch {
                    state.authMachine = authMachine
                    throw error
                }
            }

            // --- Core: build client Finished, emit the combined flight +
            // application keys + completion, and return the resumption secret. ---
            let finalActions: [TLSHandshakeAction]
            do {
                finalActions = try authMachine.finalizeClientFlight(alpn: state.context.negotiatedALPN)
            } catch {
                state.authMachine = authMachine
                throw error
            }

            // Capture the secrets derived by the core back into the adapter context
            // (read by accessors, key update, and processNewSessionTicket).
            state.context.clientApplicationSecret = authMachine.clientApplicationSecret.map(Self.symmetricKey)
            state.context.serverApplicationSecret = authMachine.serverApplicationSecret.map(Self.symmetricKey)
            state.context.exporterMasterSecret = authMachine.exporterMasterSecret.map(Self.symmetricKey)
            state.context.resumptionMasterSecret = authMachine.resumptionMasterSecret.map(Self.symmetricKey)

            // Restore the key schedule (advanced to the master-secret state) so
            // processNewSessionTicket can derive ticket PSKs (R2). The transcript is
            // no longer needed post-handshake.
            state.context.keySchedule.coreValue = authMachine.currentKeySchedule
            state.authMachine = authMachine

            outputs.append(contentsOf: try translate(actions: finalActions, state: &state))

            // Transition state
            state.handshakeState = .connected

            // Clear handshake-phase secrets no longer needed
            state.context.zeroizeSecrets()

            return outputs
        }
    }

    /// Builds the client Certificate (+ CertificateVerify), signing the
    /// CertificateVerify adapter-side via `any TLSSigningKey`, and feeds the bytes
    /// to the FSM core (which owns the transcript). Mirrors the pre-FSM ordering:
    /// Certificate is always sent (empty when no material is configured);
    /// CertificateVerify follows only when a signing key and a non-empty payload
    /// are present.
    private func buildClientCertificateFlight(
        authMachine: inout TLSClientAuthMachine<TLSFoundationProvider>,
        state: inout ClientState
    ) throws {
        // Determine the certificate payload from the negotiated type.
        // Raw Public Key (RFC 7250) needs only the signing key;
        // X.509 needs the configured certificate chain.
        let certificatePayload: [Data]
        switch state.context.negotiatedClientCertificateType {
        case .rawPublicKey:
            if let signingKey = state.configuration.signingKey {
                certificatePayload = [try SubjectPublicKeyInfo.encode(signingKey: signingKey)]
            } else {
                certificatePayload = []
            }
        case .x509:
            if state.configuration.signingKey != nil,
               let certChain = state.configuration.certificateChain,
               !certChain.isEmpty {
                certificatePayload = certChain
            } else {
                certificatePayload = []
            }
        }

        if let signingKey = state.configuration.signingKey, !certificatePayload.isEmpty {
            // Send Certificate (echoing the request context).
            let certificate = Certificate(
                certificateRequestContext: state.context.certificateRequestContext,
                certificates: certificatePayload
            )
            let certMessage = certificate.encodeAsHandshake()
            let transcriptForCV = try authMachine.foldClientCertificate(messageBytes: [UInt8](certMessage))

            // RFC 8446 §4.4.3: the client's CertificateVerify scheme must be one
            // the server offered in CertificateRequest.signature_algorithms.
            if let allowedAlgs = state.context.peerSignatureAlgorithms {
                guard allowedAlgs.contains(signingKey.scheme) else {
                    throw TLSHandshakeError.signatureVerificationFailed
                }
            }

            // Sign the transcript up to (not including) CertificateVerify.
            let signatureContent = CertificateVerify.constructSignatureContent(
                transcriptHash: Data(transcriptForCV),
                isServer: false  // CLIENT's CertificateVerify
            )
            let signature = try signingKey.sign(signatureContent)
            let certificateVerify = CertificateVerify(
                algorithm: signingKey.scheme,
                signature: signature
            )
            let cvMessage = certificateVerify.encodeAsHandshake()
            try authMachine.foldClientCertificateVerify(messageBytes: [UInt8](cvMessage))
        } else {
            // Client has no certificate material — send an empty Certificate,
            // no CertificateVerify (RFC 8446 §4.4.2).
            let emptyCertificate = Certificate(
                certificateRequestContext: state.context.certificateRequestContext,
                certificates: []
            )
            let certMessage = emptyCertificate.encodeAsHandshake()
            _ = try authMachine.foldClientCertificate(messageBytes: [UInt8](certMessage))
        }
    }

    // MARK: - Action Translation

    /// Translates the FSM core's value-type output actions into the adapter's
    /// `TLSOutput` stream, preserving order exactly. Runs the (Foundation/closure)
    /// certificate validator for `.runCertificateValidator` and propagates any
    /// validator error so the handshake halts before the server Finished.
    private func translate(
        actions: [TLSHandshakeAction],
        state: inout ClientState
    ) throws -> [TLSOutput] {
        var outputs: [TLSOutput] = []
        outputs.reserveCapacity(actions.count)
        for action in actions {
            switch action {
            case .send(let bytes, let level):
                outputs.append(.handshakeData(Data(bytes), level: level))
            case .secretsAvailable(let secrets):
                outputs.append(.keysAvailable(KeysAvailableInfo(
                    level: secrets.level,
                    clientSecret: secrets.client.map(Self.symmetricKey),
                    serverSecret: secrets.server.map(Self.symmetricKey),
                    cipherSuite: secrets.cipherSuite
                )))
            case .earlyDataEnd:
                outputs.append(.earlyDataEnd)
            case .runCertificateValidator:
                // libp2p validates the libp2p extension and extracts the PeerID
                // here, after the CertificateVerify signature has been verified.
                if let validator = state.configuration.certificateValidator,
                   let peerCerts = state.context.peerCertificates {
                    state.context.validatedPeerInfo = try validator(peerCerts)
                }
            case .handshakeComplete(let alpn, let zeroRTTAccepted):
                outputs.append(.handshakeComplete(HandshakeCompleteInfo(
                    alpn: alpn,
                    zeroRTTAccepted: zeroRTTAccepted,
                    resumptionTicket: nil
                )))
            }
        }
        return outputs
    }

    // MARK: - Process NewSessionTicket

    /// Process a NewSessionTicket message (received post-handshake)
    /// - Parameter data: The NewSessionTicket message content
    /// - Returns: The derived session ticket data for future use
    public func processNewSessionTicket(_ data: Data) throws -> SessionTicketData {
        return try state.withLock { state in
            guard state.handshakeState == .connected else {
                throw TLSHandshakeError.unexpectedMessage("NewSessionTicket received before handshake complete")
            }

            let ticket = try NewSessionTicket.decode(from: data)

            // Get resumption master secret
            guard let resumptionMasterSecret = state.context.resumptionMasterSecret,
                  let cipherSuite = state.context.cipherSuite else {
                throw TLSHandshakeError.internalError("Missing resumption master secret or cipher suite")
            }

            // Derive PSK from resumption master secret and ticket nonce
            let resumptionPSK = state.context.keySchedule.deriveResumptionPSK(
                resumptionMasterSecret: resumptionMasterSecret,
                ticketNonce: Data(ticket.ticketNonce)
            )

            // Extract max early data size from extensions
            var maxEarlyDataSize: UInt32 = 0
            for ext in ticket.extensions {
                if case .earlyData(let earlyData) = ext {
                    if case .newSessionTicket(let size) = earlyData {
                        maxEarlyDataSize = size
                    }
                }
            }

            // Create session ticket data
            let ticketData = SessionTicketData(
                ticket: Data(ticket.ticket),
                resumptionPSK: resumptionPSK,
                maxEarlyDataSize: maxEarlyDataSize,
                ticketAgeAdd: ticket.ticketAgeAdd,
                receiveTime: Date(),
                lifetime: ticket.ticketLifetime,
                cipherSuite: cipherSuite,
                serverName: state.configuration.serverName,
                alpn: state.context.negotiatedALPN
            )

            return ticketData
        }
    }

    // MARK: - Accessors

    /// Current handshake state
    public var handshakeState: ClientHandshakeState {
        state.withLock { $0.handshakeState }
    }

    /// Whether the handshake is complete
    public var isConnected: Bool {
        state.withLock { $0.handshakeState == .connected }
    }

    /// Negotiated ALPN protocol
    public var negotiatedALPN: String? {
        state.withLock { $0.context.negotiatedALPN }
    }

    /// Peer transport parameters
    public var peerTransportParameters: Data? {
        state.withLock { $0.context.peerTransportParameters }
    }

    /// Exporter master secret (available after handshake completion)
    public var exporterMasterSecret: SymmetricKey? {
        state.withLock { $0.context.exporterMasterSecret }
    }

    /// Whether PSK was used in this handshake
    public var pskUsed: Bool {
        state.withLock { $0.context.pskUsed }
    }

    /// Whether early data (0-RTT) was accepted by the server
    public var earlyDataAccepted: Bool {
        state.withLock { $0.context.earlyDataState.earlyDataAccepted }
    }

    /// Resumption master secret (for deriving new session tickets)
    public var resumptionMasterSecret: SymmetricKey? {
        state.withLock { $0.context.resumptionMasterSecret }
    }

    /// Peer certificates (raw DER data, leaf certificate first)
    public var peerCertificates: [Data]? {
        state.withLock { $0.context.peerCertificates }
    }

    /// Parsed peer leaf certificate
    public var peerCertificate: X509Certificate? {
        state.withLock { $0.context.peerCertificate }
    }

    /// Validated peer info from certificate validator callback.
    ///
    /// This contains the value returned by `TLSConfiguration.certificateValidator`
    /// after successful certificate validation (e.g., PeerID for libp2p).
    public var validatedPeerInfo: (any Sendable)? {
        state.withLock { $0.context.validatedPeerInfo }
    }
}
