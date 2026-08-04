import Synchronization
import SSLASN1
import SSLCore
import SSLCrypto
import SSLTLS
import SSLX509

/// Captures authenticated peer material without allowing callbacks to escape
/// the session's synchronization boundary.
final class CanonicalPeerCapture: Sendable {
    private struct State: Sendable {
        var certificates: [Certificate] = []
        var identity: PeerIdentity?
    }

    private let state = Mutex(State())

    func record(_ certificates: [Certificate], identity: PeerIdentity?) {
        state.withLock { value in
            value.certificates = certificates
            value.identity = identity
        }
    }

    var certificates: [Certificate]? {
        state.withLock { value in
            value.certificates.isEmpty ? nil : value.certificates
        }
    }

    var identity: PeerIdentity? {
        state.withLock { $0.identity }
    }
}

/// Certificate validation bridge used by the public facade. The cryptographic
/// proof and X.509 path are always evaluated by `swift-ssl`; the application
/// callback is an additional policy gate and never replaces that proof.
struct CanonicalServerCertificateValidator: TLS13ServerCertificateValidating {
    private let pathValidator: (any TLS13ServerCertificateValidating)?
    private let callback:
        (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?
    private let capture: CanonicalPeerCapture

    init(
        pathValidator: (any TLS13ServerCertificateValidating)?,
        callback: (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?,
        capture: CanonicalPeerCapture
    ) {
        self.pathValidator = pathValidator
        self.callback = callback
        self.capture = capture
    }

    func validate(
        _ message: borrowing TLS13CertificateMessage,
        serverName: Span<UInt8>?,
        at instant: VerificationInstant
    ) throws(TLS13ServerCertificateValidationError) -> SubjectPublicKeyInfo {
        let certificates = CanonicalTLSConversion.certificates(from: message)
        let publicKey: SubjectPublicKeyInfo
        if let pathValidator {
            publicKey = try pathValidator.validate(
                message,
                serverName: serverName,
                at: instant
            )
        } else {
            guard let first = message.entries.first else {
                throw .invalidCertificateMessage
            }
            do {
                publicKey = try X509Certificate(der: first.certificate.span)
                    .subjectPublicKeyInfo
            } catch let error {
                throw .certificate(index: 0, error)
            }
        }

        if let callback {
            do {
                let identity = try callback(certificates)
                capture.record(certificates, identity: identity)
            } catch {
                throw .invalidCertificateMessage
            }
        } else {
            capture.record(certificates, identity: nil)
        }
        return publicKey
    }
}

struct CanonicalClientCertificateValidator: TLS13ClientCertificateValidating {
    private let pathValidator: (any TLS13ClientCertificateValidating)?
    private let callback:
        (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?
    private let capture: CanonicalPeerCapture

    init(
        pathValidator: (any TLS13ClientCertificateValidating)?,
        callback: (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?,
        capture: CanonicalPeerCapture
    ) {
        self.pathValidator = pathValidator
        self.callback = callback
        self.capture = capture
    }

    func validate(
        _ message: borrowing TLS13CertificateMessage,
        at instant: VerificationInstant
    ) throws(TLS13ClientCertificateValidationError) -> TLS13ValidatedClientCertificate {
        let certificates = CanonicalTLSConversion.certificates(from: message)
        let validated: TLS13ValidatedClientCertificate
        if let pathValidator {
            validated = try pathValidator.validate(message, at: instant)
        } else {
            guard let first = message.entries.first else {
                throw .invalidCertificateMessage
            }
            do {
                let certificate = try X509Certificate(der: first.certificate.span)
                validated = TLS13ValidatedClientCertificate(
                    certificateMessage: TLS13CertificateMessage(copying: message),
                    leafSubjectPublicKeyInfo: certificate.subjectPublicKeyInfo
                )
            } catch let error {
                throw .certificate(index: 0, error)
            }
        }

        if let callback {
            do {
                let identity = try callback(certificates)
                capture.record(certificates, identity: identity)
            } catch {
                throw .invalidCertificateMessage
            }
        } else {
            capture.record(certificates, identity: nil)
        }
        return validated
    }
}

enum CanonicalTLSConversion {
    static func string(from bytes: Span<UInt8>) -> String {
        var value: [UInt8] = []
        value.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            value.append(bytes[index])
            index += 1
        }
        return String(decoding: value, as: UTF8.self)
    }

    static func applicationProtocols(
        _ values: [String]
    ) throws(TLSError) -> ContiguousArray<TLS13ApplicationProtocol> {
        var result = ContiguousArray<TLS13ApplicationProtocol>()
        result.reserveCapacity(values.count)
        for value in values {
            let bytes = Array(value.utf8)
            do {
                result.append(try TLS13ApplicationProtocol(identifier: bytes.span))
            } catch {
                throw .invalidConfiguration(reason: "invalid ALPN identifier")
            }
        }
        return result
    }

    static func certificateEntries(
        _ certificates: [Certificate]
    ) throws(TLSError) -> ContiguousArray<TLS13CertificateEntry> {
        guard !certificates.isEmpty else {
            throw .invalidConfiguration(reason: "certificate chain is empty")
        }
        var result = ContiguousArray<TLS13CertificateEntry>()
        result.reserveCapacity(certificates.count)
        for certificate in certificates {
            do {
                result.append(try TLS13CertificateEntry(certificateDER: certificate.der.span))
            } catch {
                throw .invalidConfiguration(reason: "invalid certificate chain")
            }
        }
        return result
    }

    static func signingKey(
        _ identity: TLSIdentity
    ) throws(TLSError) -> TLS13SigningKey {
        do {
            switch identity.keyType {
            case .ecdsaP256:
                return TLS13SigningKey(
                    p256: try P256PrivateKey(bytes: identity.privateKey.span)
                )
            case .ecdsaP384:
                throw TLSError.invalidConfiguration(
                    reason: "P-384 signing is not in the current public TLS profile"
                )
            case .ed25519:
                return TLS13SigningKey(
                    ed25519: try Ed25519PrivateKey(seed: identity.privateKey.span)
                )
            }
        } catch let error as TLSError {
            throw error
        } catch {
            throw .invalidConfiguration(reason: "invalid private signing key")
        }
    }

    static func verificationInstant() throws(TLSError) -> VerificationInstant {
        do {
            return try SystemWallClock().now()
        } catch {
            throw .invalidConfiguration(reason: "wall clock unavailable")
        }
    }

    static func randomBytes(count: Int) throws(TLSError) -> ContiguousArray<UInt8> {
        var bytes = ContiguousArray<UInt8>(repeating: 0, count: count)
        do {
            var destination = bytes.mutableSpan
            try SystemEntropySource().fill(&destination)
        } catch {
            throw .invalidConfiguration(reason: "entropy unavailable")
        }
        return bytes
    }

    static func certificates(
        from message: borrowing TLS13CertificateMessage
    ) -> [Certificate] {
        var result: [Certificate] = []
        result.reserveCapacity(message.entries.count)
        for entry in message.entries {
            var der: [UInt8] = []
            der.reserveCapacity(entry.certificate.count)
            let bytes = entry.certificate.span
            var index = 0
            while index < bytes.count {
                der.append(bytes[index])
                index += 1
            }
            result.append(Certificate(der: der))
        }
        return result
    }
}

struct CanonicalTLSClientFactory: ~Copyable, Sendable {
    let handshake: TLS13ClientHandshake
    let capture: CanonicalPeerCapture

    init(configuration: TLSConfiguration) throws(TLSError) {
        let instant = try CanonicalTLSConversion.verificationInstant()
        let random = try CanonicalTLSConversion.randomBytes(count: 32)
        let ephemeral: X25519PrivateKey
        do {
            ephemeral = try X25519PrivateKey.generate()
        } catch {
            throw .invalidConfiguration(reason: "ephemeral key generation failed")
        }
        let capture = CanonicalPeerCapture()
        let pathValidator = try CanonicalTLSValidators.server(
            configuration: configuration
        )
        let protocols = try CanonicalTLSConversion.applicationProtocols(
            configuration.alpnProtocols
        )
        let serverNameBytes = configuration.serverName?.utf8Array
        let clientIdentity: TLS13ClientIdentity?
        if let identity = configuration.identity {
            do {
                clientIdentity = try TLS13ClientIdentity(
                    certificateEntries: CanonicalTLSConversion.certificateEntries(
                        identity.certificateChain
                    ),
                    signingKey: CanonicalTLSConversion.signingKey(identity),
                    verificationInstant: instant
                )
            } catch {
                throw .invalidConfiguration(reason: "invalid TLS client identity")
            }
        } else {
            clientIdentity = nil
        }
        let handshake: TLS13ClientHandshake
        do {
            handshake = try TLS13ClientHandshake(
                random: random.span,
                ephemeralKey: ephemeral,
                certificateValidator: CanonicalServerCertificateValidator(
                    pathValidator: pathValidator,
                    callback: configuration.certificateValidator,
                    capture: capture
                ),
                clientIdentity: clientIdentity,
                applicationProtocols: protocols,
                serverName: serverNameBytes?.span,
                verificationInstant: instant
            )
        } catch {
            throw .invalidConfiguration(reason: "TLS client initialization failed")
        }
        self.handshake = handshake
        self.capture = capture
    }
}

struct CanonicalTLSServerFactory: ~Copyable, Sendable {
    let handshake: TLS13ServerHandshake
    let capture: CanonicalPeerCapture

    init(configuration: TLSConfiguration) throws(TLSError) {
        guard let identity = configuration.identity else {
            throw .invalidConfiguration(reason: "server identity is required")
        }
        let instant = try CanonicalTLSConversion.verificationInstant()
        let random = try CanonicalTLSConversion.randomBytes(count: 32)
        let ephemeral: X25519PrivateKey
        do {
            ephemeral = try X25519PrivateKey.generate()
        } catch {
            throw .invalidConfiguration(reason: "ephemeral key generation failed")
        }
        let entries = try CanonicalTLSConversion.certificateEntries(
            identity.certificateChain
        )
        let signingKey = try CanonicalTLSConversion.signingKey(identity)
        let capture = CanonicalPeerCapture()
        let clientAuthentication: TLS13ClientAuthenticationConfiguration?
        if configuration.requireClientCertificate {
            let validator = try CanonicalTLSValidators.client(
                configuration: configuration,
                capture: capture
            )
            clientAuthentication = TLS13ClientAuthenticationConfiguration(
                requirement: .required,
                validator: validator
            )
        } else {
            clientAuthentication = nil
        }
        let selector: ServerPreferredTLS13ApplicationProtocolSelector?
        if configuration.alpnProtocols.isEmpty {
            selector = nil
        } else {
            do {
                selector = try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: CanonicalTLSConversion.applicationProtocols(
                        configuration.alpnProtocols
                    )
                )
            } catch {
                throw .invalidConfiguration(reason: "invalid ALPN configuration")
            }
        }
        let handshake: TLS13ServerHandshake
        do {
            handshake = try TLS13ServerHandshake(
                random: random.span,
                ephemeralKey: ephemeral,
                certificateEntries: entries,
                signingKey: signingKey,
                verificationInstant: instant,
                applicationProtocolSelector: selector,
                clientAuthentication: clientAuthentication
            )
        } catch {
            throw .invalidConfiguration(reason: "TLS server initialization failed")
        }
        self.handshake = handshake
        self.capture = capture
    }
}

enum CanonicalTLSValidators {
    static func server(
        configuration: TLSConfiguration
    ) throws(TLSError) -> (any TLS13ServerCertificateValidating)? {
        guard configuration.verifyPeer else { return nil }
        guard !configuration.trustRoots.x509Roots.isEmpty else {
            guard configuration.certificateValidator != nil else {
                throw .invalidConfiguration(
                    reason: "verifyPeer requires trust roots or a certificate validator"
                )
            }
            return nil
        }
        let anchors = try parseAnchors(configuration.trustRoots.x509Roots)
        do {
            return try RFC5280TLS13ServerCertificateValidator(
                trustAnchors: anchors
            )
        } catch {
            throw .invalidConfiguration(reason: "invalid X.509 trust anchors")
        }
    }

    static func client(
        configuration: TLSConfiguration,
        capture: CanonicalPeerCapture
    ) throws(TLSError) -> any TLS13ClientCertificateValidating {
        let path: (any TLS13ClientCertificateValidating)?
        if configuration.verifyPeer && !configuration.trustRoots.x509Roots.isEmpty {
            let anchors = try parseAnchors(configuration.trustRoots.x509Roots)
            do {
                path = try RFC5280TLS13ClientCertificateValidator(
                    trustAnchors: anchors
                )
            } catch {
                throw .invalidConfiguration(reason: "invalid X.509 trust anchors")
            }
        } else {
            path = nil
        }
        return CanonicalClientCertificateValidator(
            pathValidator: path,
            callback: configuration.certificateValidator,
            capture: capture
        )
    }

    private static func parseAnchors(
        _ certificates: [Certificate]
    ) throws(TLSError) -> ContiguousArray<X509Certificate> {
        var result = ContiguousArray<X509Certificate>()
        result.reserveCapacity(certificates.count)
        for certificate in certificates {
            do {
                result.append(try X509Certificate(der: certificate.der.span))
            } catch {
                throw .invalidConfiguration(reason: "invalid X.509 trust anchor")
            }
        }
        return result
    }
}

extension String {
    fileprivate var utf8Array: [UInt8] { Array(utf8) }
}

extension TLS13HandshakeEngineError {
    var facadeError: TLSError {
        switch self {
        case .invalidState: return .connectionClosed
        case .invalidConfiguration: return .invalidConfiguration(reason: "invalid TLS configuration")
        case .malformedInput: return .protocolFailure(reason: "malformed TLS input")
        case .certificateValidation, .clientCertificateValidation,
             .certificateKeyMismatch, .certificateNotValid,
             .certificateVerificationFailed, .certificateVerifyFailure:
            return .verificationFailed(reason: "certificate verification failed")
        case .record(.authenticationFailed):
            return .verificationFailed(reason: "record authentication failed")
        case .output(.outOfBounds), .output(.negativeCount), .output(.offsetOverflow):
            return .bufferOverflow
        default:
#if hasFeature(Embedded)
            return .protocolFailure(reason: "TLS handshake failed")
#else
            return .protocolFailure(reason: String(describing: self))
#endif
        }
    }
}
