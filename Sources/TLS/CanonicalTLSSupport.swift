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
    static func preferredCertificateType(
        _ values: [TLSCertificateTypes.CertificateType],
        role: String
    ) throws(TLSError) -> TLSCertificateTypes.CertificateType {
        guard let value = values.first else {
            throw .invalidConfiguration(reason: "\(role) certificate types are empty")
        }
        return value
    }

    static func singleCertificateType(
        _ values: [TLSCertificateTypes.CertificateType],
        role: String
    ) throws(TLSError) -> TLSCertificateTypes.CertificateType {
        guard values.count == 1, let value = values.first else {
            throw .invalidConfiguration(
                reason: "\(role) requires exactly one certificate type"
            )
        }
        return value
    }

    static func toTLS13CertificateType(
        _ value: TLSCertificateTypes.CertificateType
    ) -> TLS13CertificateType {
        switch value {
        case .x509: .x509
        case .rawPublicKey: .rawPublicKey
        }
    }

    static func toTLS13CertificateTypes(
        _ values: [TLSCertificateTypes.CertificateType]
    ) throws(TLSError) -> ContiguousArray<TLS13CertificateType> {
        guard !values.isEmpty else {
            throw .invalidConfiguration(reason: "certificate types are empty")
        }
        var result = ContiguousArray<TLS13CertificateType>()
        result.reserveCapacity(values.count)
        for value in values {
            let coreValue = toTLS13CertificateType(value)
            if !result.contains(coreValue) {
                result.append(coreValue)
            }
        }
        return result
    }

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

    static func localCredentialProvider(
        _ identity: TLSIdentity,
        certificateType: TLSCertificateTypes.CertificateType
    ) throws(TLSError) -> CanonicalTLSLocalCredentialProvider {
        guard certificateType == .rawPublicKey,
            identity.certificateChain.isEmpty,
            let rawPublicKey = identity.rawPublicKey
        else {
            throw .invalidConfiguration(
                reason: "raw-public-key identity requires SubjectPublicKeyInfo and no X.509 chain"
            )
        }
        guard !identity.credentialIdentifier.isEmpty else {
            throw .invalidConfiguration(reason: "credential identifier is empty")
        }
        let signingKey = try signingKey(identity)
        let subjectPublicKeyInfo: SubjectPublicKeyInfo
        do {
            subjectPublicKeyInfo = try SubjectPublicKeyInfo(der: rawPublicKey.der.span)
            let derivedPublicKey = try signingKey.publicKeyBytes()
            let matches = subjectPublicKeyInfo.withPublicKeyBytes { encoded in
                ConstantTime.equal(encoded, derivedPublicKey.span)
            }
            guard matches else {
                throw TLSError.invalidConfiguration(
                    reason: "raw-public-key identity does not match its private key"
                )
            }
        } catch let error as TLSError {
            throw error
        } catch {
            throw .invalidConfiguration(reason: "invalid raw-public-key identity")
        }
        let credential = TLSCredential(
            identifier: identity.credentialIdentifier,
            rawPublicKey: rawPublicKey,
            certificateType: .rawPublicKey,
            signatureScheme: TLSSignatureScheme(rawValue: signingKey.signatureScheme.rawValue)
        )
        return CanonicalTLSLocalCredentialProvider(
            credential: credential,
            signingKey: consume signingKey
        )
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

/// Local raw-public-key capability provider. It performs only deterministic
/// credential selection and signing; peer trust remains an explicit caller
/// decision and is never accepted implicitly.
struct CanonicalTLSLocalCredentialProvider: ~Copyable, Sendable {
    let credential: TLSCredential
    let signingKey: TLS13SigningKey

    init(credential: TLSCredential, signingKey: consuming TLS13SigningKey) {
        self.credential = credential
        self.signingKey = consume signingKey
    }

    borrowing func response(
        for request: TLSCapabilityRequest
    ) throws(TLSError) -> TLSCapabilityResponse? {
        switch request {
        case .peerTrustEvaluation:
            return nil
        case .credentialSelection(let request):
            guard request.certificateTypes.contains(credential.certificateType),
                request.signatureSchemes.contains(credential.signatureScheme)
            else {
                return .credentialUnavailable(request.token)
            }
            return .credentialSelected(request.token, credential)
        case .signature(let request):
            guard request.credentialIdentifier == credential.identifier,
                request.signatureScheme == credential.signatureScheme
            else {
                return .signatureRejected(request.token)
            }
            do {
                let signature = try signingKey.sign(message: request.message.span)
                return .signature(request.token, Array(signature))
            } catch {
                throw .internalError(reason: "local signing operation failed")
            }
        }
    }
}

/// Validates configured RFC 7250 trust anchors at the capability boundary.
/// The TLS mechanism still verifies the CertificateVerify proof; this provider
/// only decides whether the presented SubjectPublicKeyInfo is trusted.
struct CanonicalTLSPeerTrustProvider: Sendable, Hashable {
    let trustedKeys: [Certificate]
    let acceptsAnyKey: Bool

    init(roots: [Certificate], verifyPeer: Bool) throws(TLSError) {
        guard !verifyPeer || !roots.isEmpty else {
            throw .invalidConfiguration(reason: "raw-public-key trust roots are empty")
        }
        for root in roots {
            do {
                _ = try SubjectPublicKeyInfo(der: root.der.span)
            } catch {
                throw .invalidConfiguration(
                    reason: "raw-public-key trust root is not SubjectPublicKeyInfo"
                )
            }
        }
        self.trustedKeys = roots
        self.acceptsAnyKey = !verifyPeer
    }

    func response(
        for request: TLSCapabilityRequest
    ) -> TLSCapabilityResponse? {
        guard case .peerTrustEvaluation(let request) = request,
            request.certificateType == .rawPublicKey,
            request.certificates.count == 1
        else {
            return nil
        }
        let presented = request.certificates[0]
        let trusted = acceptsAnyKey || trustedKeys.contains { trusted in
            Self.matches(trusted, presented)
        }
        return trusted
            ? .peerTrustAccepted(request.token)
            : .peerTrustRejected(request.token)
    }

    private static func matches(
        _ trusted: Certificate,
        _ presented: Certificate
    ) -> Bool {
        do {
            let trustedKey = try SubjectPublicKeyInfo(der: trusted.der.span)
            let presentedKey = try SubjectPublicKeyInfo(der: presented.der.span)
            guard trustedKey.algorithm == presentedKey.algorithm else {
                return false
            }
            return trustedKey.withPublicKeyBytes { trustedBytes in
                presentedKey.withPublicKeyBytes { presentedBytes in
                    ConstantTime.equal(trustedBytes, presentedBytes)
                }
            }
        } catch {
            return false
        }
    }
}

struct CanonicalTLSClientFactory: ~Copyable, Sendable {
    let handshake: TLS13ClientHandshake
    let capture: CanonicalPeerCapture
    let verificationInstant: VerificationInstant
    let localCredentialProvider: CanonicalTLSLocalCredentialProvider?
    let peerTrustProvider: CanonicalTLSPeerTrustProvider?
    let peerCertificateValidator: (any TLS13ServerCertificateValidating)?
    let certificateValidator:
        (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?

    init(
        configuration: TLSConfiguration,
        resumptionState: TLSResumptionState? = nil
    ) throws(TLSError) {
        let instant = try CanonicalTLSConversion.verificationInstant()
        let random = try CanonicalTLSConversion.randomBytes(count: 32)
        let ephemeral: X25519PrivateKey
        do {
            ephemeral = try X25519PrivateKey.generate()
        } catch {
            throw .invalidConfiguration(reason: "ephemeral key generation failed")
        }
        let capture = CanonicalPeerCapture()
        let peerCertificateType = try CanonicalTLSConversion.singleCertificateType(
            configuration.certificateTypes.peer,
            role: "peer"
        )
        let localCertificateType = try CanonicalTLSConversion.singleCertificateType(
            configuration.certificateTypes.local,
            role: "local"
        )
        let pathValidator: (any TLS13ServerCertificateValidating)?
        var peerTrustProvider: CanonicalTLSPeerTrustProvider? = nil
        if peerCertificateType == .x509 {
            guard configuration.trustRoots.rawPublicKeys.isEmpty else {
                throw .invalidConfiguration(
                    reason: "raw-public-key roots require raw-public-key peer certificates"
                )
            }
            pathValidator = try CanonicalTLSValidators.server(
                configuration: configuration
            )
        } else {
            guard configuration.trustRoots.x509Roots.isEmpty else {
                throw .invalidConfiguration(
                    reason: "X.509 roots cannot validate raw-public-key certificates"
                )
            }
            if !configuration.trustRoots.rawPublicKeys.isEmpty {
                guard configuration.verifyPeer else {
                    throw .invalidConfiguration(
                        reason: "raw-public-key trust roots require verifyPeer"
                    )
                }
                peerTrustProvider = try CanonicalTLSPeerTrustProvider(
                    roots: configuration.trustRoots.rawPublicKeys,
                    verifyPeer: configuration.verifyPeer
                )
            } else if !configuration.verifyPeer {
                peerTrustProvider = try CanonicalTLSPeerTrustProvider(
                    roots: [],
                    verifyPeer: false
                )
            }
            pathValidator = nil
        }
        let protocols = try CanonicalTLSConversion.applicationProtocols(
            configuration.alpnProtocols
        )
        let serverNameBytes = configuration.serverName?.utf8Array
        let coreResumptionState: TLS13ResumptionState?
        if let resumptionState {
            coreResumptionState = try resumptionState.takeCore()
        } else {
            coreResumptionState = nil
        }
        let clientIdentity: TLS13ClientIdentity?
        var localCredentialProvider: CanonicalTLSLocalCredentialProvider? = nil
        let externalClientCredential: TLS13ExternalClientCredential?
        if localCertificateType == .rawPublicKey,
            let identity = configuration.identity
        {
            externalClientCredential = TLS13ExternalClientCredential(certificateType: .rawPublicKey)
            localCredentialProvider = try CanonicalTLSConversion.localCredentialProvider(
                identity,
                certificateType: localCertificateType
            )
            clientIdentity = nil
        } else if localCertificateType == .rawPublicKey {
            // Do not advertise a client certificate type when there is no
            // local credential to satisfy a future CertificateRequest.
            externalClientCredential = nil
            clientIdentity = nil
        } else if let identity = configuration.identity {
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
            externalClientCredential = nil
        } else {
            clientIdentity = nil
            externalClientCredential = nil
        }
        let handshake: TLS13ClientHandshake
        do {
            if peerCertificateType == .rawPublicKey {
                handshake = try TLS13ClientHandshake(
                    random: random.span,
                    ephemeralKey: ephemeral,
                    externalServerTrust: TLS13ExternalServerTrust(
                        certificateType: .rawPublicKey
                    ),
                    clientIdentity: clientIdentity,
                    externalClientCredential: externalClientCredential,
                    applicationProtocols: protocols,
                    serverName: serverNameBytes?.span,
                    verificationInstant: instant,
                    resumptionState: consume coreResumptionState
                )
            } else if configuration.certificateValidator != nil {
                handshake = try TLS13ClientHandshake(
                    random: random.span,
                    ephemeralKey: ephemeral,
                    externalServerTrust: TLS13ExternalServerTrust(
                        certificateType: .x509
                    ),
                    clientIdentity: clientIdentity,
                    externalClientCredential: externalClientCredential,
                    applicationProtocols: protocols,
                    serverName: serverNameBytes?.span,
                    verificationInstant: instant,
                    resumptionState: consume coreResumptionState
                )
            } else {
                handshake = try TLS13ClientHandshake(
                    random: random.span,
                    ephemeralKey: ephemeral,
                    certificateValidator: CanonicalServerCertificateValidator(
                        pathValidator: pathValidator,
                        callback: configuration.certificateValidator,
                        capture: capture
                    ),
                    clientIdentity: clientIdentity,
                    externalClientCredential: externalClientCredential,
                    applicationProtocols: protocols,
                    serverName: serverNameBytes?.span,
                    verificationInstant: instant,
                    resumptionState: consume coreResumptionState
                )
            }
        } catch {
            throw .invalidConfiguration(reason: "TLS client initialization failed")
        }
        self.handshake = handshake
        self.capture = capture
        self.verificationInstant = instant
        self.localCredentialProvider = localCredentialProvider
        self.peerTrustProvider = peerTrustProvider
        self.peerCertificateValidator = pathValidator
        self.certificateValidator = configuration.certificateValidator
    }
}

struct CanonicalTLSServerFactory: ~Copyable, Sendable {
    let handshake: TLS13ServerHandshake
    let capture: CanonicalPeerCapture
    let verificationInstant: VerificationInstant
    let localCredentialProvider: CanonicalTLSLocalCredentialProvider?
    let peerTrustProvider: CanonicalTLSPeerTrustProvider?
    let peerCertificateValidator: (any TLS13ClientCertificateValidating)?
    let certificateValidator:
        (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?

    init(
        configuration: TLSConfiguration,
        resumptionState: TLSResumptionState? = nil
    ) throws(TLSError) {
        let resumptionIdentity: ContiguousArray<UInt8>
        let resumptionPSK: ContiguousArray<UInt8>
        let hasResumptionState = resumptionState != nil
        if let resumptionState {
            resumptionIdentity = try resumptionState.copyTicketBytes()
            resumptionPSK = try resumptionState.consumePSKBytes()
        } else {
            resumptionIdentity = []
            resumptionPSK = []
        }
        let resumptionIssuedAt = resumptionState?.issuedAt
        let resumptionLifetime = resumptionState?.lifetime
        let resumptionAgeAdd = resumptionState?.ageAdd
        let resumptionMaximumEarlyDataByteCount =
            resumptionState?.maximumEarlyDataByteCount ?? 0
        let resumptionApplicationProtocol = resumptionState?.applicationProtocol
        let localCertificateType = try CanonicalTLSConversion.preferredCertificateType(
            configuration.certificateTypes.local,
            role: "local"
        )
        let peerCertificateType = try CanonicalTLSConversion.singleCertificateType(
            configuration.certificateTypes.peer,
            role: "peer"
        )
        let identity = configuration.identity
        if localCertificateType == .x509, identity == nil {
            throw .invalidConfiguration(reason: "server X.509 identity is required")
        }
        if peerCertificateType == .rawPublicKey, !configuration.trustRoots.x509Roots.isEmpty {
            throw .invalidConfiguration(
                reason: "X.509 roots cannot validate a raw-public-key peer"
            )
        }
        if !configuration.trustRoots.rawPublicKeys.isEmpty {
            guard peerCertificateType == .rawPublicKey else {
                throw .invalidConfiguration(
                    reason: "raw-public-key trust roots require raw-public-key peer certificates"
                )
            }
            guard configuration.requireClientCertificate else {
                throw .invalidConfiguration(
                    reason: "raw-public-key trust roots require client certificates"
                )
            }
            guard configuration.verifyPeer else {
                throw .invalidConfiguration(
                    reason: "raw-public-key trust roots require verifyPeer"
                )
            }
        }
        let instant = try CanonicalTLSConversion.verificationInstant()
        let random = try CanonicalTLSConversion.randomBytes(count: 32)
        let ephemeral: X25519PrivateKey
        do {
            ephemeral = try X25519PrivateKey.generate()
        } catch {
            throw .invalidConfiguration(reason: "ephemeral key generation failed")
        }
        let capture = CanonicalPeerCapture()
        let peerTrustProvider: CanonicalTLSPeerTrustProvider?
        if !configuration.trustRoots.rawPublicKeys.isEmpty {
            peerTrustProvider = try CanonicalTLSPeerTrustProvider(
                roots: configuration.trustRoots.rawPublicKeys,
                verifyPeer: configuration.verifyPeer
            )
        } else if peerCertificateType == .rawPublicKey && !configuration.verifyPeer {
            peerTrustProvider = try CanonicalTLSPeerTrustProvider(
                roots: [],
                verifyPeer: false
            )
        } else {
            peerTrustProvider = nil
        }
        let clientAuthentication: TLS13ClientAuthenticationConfiguration?
        let peerCertificateValidator: (any TLS13ClientCertificateValidating)?
        if configuration.requireClientCertificate {
            if peerCertificateType == .rawPublicKey {
                peerCertificateValidator = nil
                clientAuthentication = TLS13ClientAuthenticationConfiguration(
                    externalTrust: TLS13ExternalClientTrust(
                        requirement: .required,
                        certificateType: .rawPublicKey
                    )
                )
            } else if configuration.certificateValidator != nil {
                let validator = try CanonicalTLSValidators.client(
                    configuration: configuration,
                    capture: capture,
                    includePolicyCallback: false
                )
                peerCertificateValidator = validator
                clientAuthentication = TLS13ClientAuthenticationConfiguration(
                    externalTrust: TLS13ExternalClientTrust(
                        requirement: .required,
                        certificateType: .x509
                    )
                )
            } else {
                let validator = try CanonicalTLSValidators.client(
                    configuration: configuration,
                    capture: capture
                )
                peerCertificateValidator = nil
                clientAuthentication = TLS13ClientAuthenticationConfiguration(
                    requirement: .required,
                    validator: validator
                )
            }
        } else {
            peerCertificateValidator = nil
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
        var localCredentialProvider: CanonicalTLSLocalCredentialProvider? = nil
        do {
            // The canonical constructor copies the resumption bytes before it
            // returns. The pointers are used only for that synchronous call;
            // the backing arrays remain alive for the entire initializer.
            let identityPointer = resumptionIdentity.withUnsafeBufferPointer {
                $0.baseAddress
            }
            let pskPointer = resumptionPSK.withUnsafeBufferPointer {
                $0.baseAddress
            }
            let handshake: TLS13ServerHandshake
            if localCertificateType == .rawPublicKey {
                if let identity {
                    localCredentialProvider = try CanonicalTLSConversion.localCredentialProvider(
                        identity,
                        certificateType: localCertificateType
                    )
                }
                handshake = try TLS13ServerHandshake(
                    random: random.span,
                    ephemeralKey: ephemeral,
                    externalServerCredential: TLS13ExternalServerCredential(
                        certificateTypes: try CanonicalTLSConversion.toTLS13CertificateTypes(
                            configuration.certificateTypes.local
                        )
                    ),
                    verificationInstant: instant,
                    applicationProtocolSelector: selector,
                    clientAuthentication: clientAuthentication,
                    resumptionIdentity: hasResumptionState
                        ? Span(_unsafeStart: identityPointer!, count: resumptionIdentity.count)
                        : nil,
                    resumptionPSK: hasResumptionState
                        ? Span(_unsafeStart: pskPointer!, count: resumptionPSK.count)
                        : nil,
                    resumptionIssuedAt: resumptionIssuedAt,
                    resumptionLifetime: resumptionLifetime,
                    resumptionAgeAdd: resumptionAgeAdd,
                    resumptionMaximumEarlyDataByteCount:
                        resumptionMaximumEarlyDataByteCount,
                    resumptionApplicationProtocol: resumptionApplicationProtocol
                )
            } else {
                guard let identity else {
                    throw TLSError.invalidConfiguration(
                        reason: "server X.509 identity is required"
                    )
                }
                let entries = try CanonicalTLSConversion.certificateEntries(
                    identity.certificateChain
                )
                let signingKey = try CanonicalTLSConversion.signingKey(identity)
                handshake = try TLS13ServerHandshake(
                    random: random.span,
                    ephemeralKey: ephemeral,
                    certificateEntries: entries,
                    signingKey: signingKey,
                    verificationInstant: instant,
                    applicationProtocolSelector: selector,
                    clientAuthentication: clientAuthentication,
                    resumptionIdentity: hasResumptionState
                        ? Span(_unsafeStart: identityPointer!, count: resumptionIdentity.count)
                        : nil,
                    resumptionPSK: hasResumptionState
                        ? Span(_unsafeStart: pskPointer!, count: resumptionPSK.count)
                        : nil,
                    resumptionIssuedAt: resumptionIssuedAt,
                    resumptionLifetime: resumptionLifetime,
                    resumptionAgeAdd: resumptionAgeAdd,
                    resumptionMaximumEarlyDataByteCount:
                        resumptionMaximumEarlyDataByteCount,
                    resumptionApplicationProtocol: resumptionApplicationProtocol
                )
            }
            self.handshake = handshake
        } catch let error as TLS13HandshakeEngineError {
            throw .invalidConfiguration(
                reason: "TLS server initialization failed: \(error)"
            )
        } catch {
#if hasFeature(Embedded)
            throw .invalidConfiguration(reason: "TLS server initialization failed")
#else
            throw .invalidConfiguration(
                reason: "TLS server initialization failed: \(String(describing: error))"
            )
#endif
        }
        self.capture = capture
        self.verificationInstant = instant
        self.localCredentialProvider = localCredentialProvider
        self.peerTrustProvider = peerTrustProvider
        self.peerCertificateValidator = peerCertificateValidator
        self.certificateValidator = configuration.certificateValidator
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
        capture: CanonicalPeerCapture,
        includePolicyCallback: Bool = true
    ) throws(TLSError) -> any TLS13ClientCertificateValidating {
        guard !configuration.verifyPeer
            || !configuration.trustRoots.x509Roots.isEmpty
            || configuration.certificateValidator != nil
        else {
            throw .invalidConfiguration(
                reason: "verifyPeer requires client trust roots or a certificate validator"
            )
        }
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
            callback: includePolicyCallback ? configuration.certificateValidator : nil,
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
