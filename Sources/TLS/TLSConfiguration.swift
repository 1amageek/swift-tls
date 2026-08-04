import SSLCore
import SSLTLS
import SSLX509

/// Configuration for the public Stream TLS session facade.
///
/// The facade contains policy and external capability hooks only. Wire codecs,
/// transcript state, key schedule, record protection, and certificate parsing
/// are provided by `swift-ssl`.
public struct TLSConfiguration: Sendable {
    public var serverName: String?
    public var alpnProtocols: [String]
    public var verifyPeer: Bool
    public var identity: TLSIdentity?
    public var trustRoots: TLSTrustRoots
    public var certificateTypes: TLSCertificateTypes
    public var requireClientCertificate: Bool
    public var certificateValidator:
        (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?

    public init(
        serverName: String? = nil,
        alpnProtocols: [String] = [],
        verifyPeer: Bool = true,
        identity: TLSIdentity? = nil,
        trustRoots: TLSTrustRoots = .none,
        certificateTypes: TLSCertificateTypes = .x509,
        requireClientCertificate: Bool = false,
        certificateValidator:
          (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)? = nil
    ) {
        self.serverName = serverName
        self.alpnProtocols = alpnProtocols
        self.verifyPeer = verifyPeer
        self.identity = identity
        self.trustRoots = trustRoots
        self.certificateTypes = certificateTypes
        self.requireClientCertificate = requireClientCertificate
        self.certificateValidator = certificateValidator
    }

    public static func client(
        serverName: String? = nil,
        alpn: [String] = []
    ) -> TLSConfiguration {
        TLSConfiguration(serverName: serverName, alpnProtocols: alpn)
    }

    public static func server(
        identity: TLSIdentity,
        alpn: [String] = []
    ) -> TLSConfiguration {
        TLSConfiguration(alpnProtocols: alpn, identity: identity)
    }
}

extension TLSConfiguration {
    func makeClientFactory() throws(TLSError) -> CanonicalTLSClientFactory {
        try CanonicalTLSClientFactory(configuration: self)
    }

    func makeServerFactory() throws(TLSError) -> CanonicalTLSServerFactory {
        try CanonicalTLSServerFactory(configuration: self)
    }
}
