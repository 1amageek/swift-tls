/// Configuration for `TLSClient`/`TLSServer`/`DTLSClient`/`DTLSServer`.
///
/// The facade configuration is `[UInt8]`-currency and free of swift-certificates /
/// swift-crypto types. It is translated into the engine configuration at the
/// boundary; the engine remains the single source of TLS behaviour.

#if !hasFeature(Embedded)
import TLSCore
#endif

public struct TLSConfiguration: Sendable {
    /// Server name for SNI (client only).
    public var serverName: String?

    /// Application-Layer Protocol Negotiation protocols, in preference order.
    public var alpnProtocols: [String]

    /// Whether to authenticate the peer (default: `true`).
    public var verifyPeer: Bool

    /// Local authentication material (signing key + chain). Servers require it;
    /// clients need it only for mutual TLS.
    public var identity: TLSIdentity?

    /// X.509 roots and/or raw public keys used to authenticate the peer.
    public var trustRoots: TLSTrustRoots

    /// Which certificate encodings this endpoint presents/accepts (RFC 7250).
    public var certificateTypes: TLSCertificateTypes

    /// Require a client certificate (server only); enables mutual TLS.
    public var requireClientCertificate: Bool

    /// Custom peer-certificate validator, called after the mandatory
    /// CertificateVerify signature check succeeds. Returns an application
    /// `PeerIdentity`, or `nil` to defer to TLS-level verification. Throwing
    /// aborts the handshake.
    public var certificateValidator: (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)?

    public init(
        serverName: String? = nil,
        alpnProtocols: [String] = [],
        verifyPeer: Bool = true,
        identity: TLSIdentity? = nil,
        trustRoots: TLSTrustRoots = .none,
        certificateTypes: TLSCertificateTypes = .x509,
        requireClientCertificate: Bool = false,
        certificateValidator: (@Sendable ([Certificate]) throws(TLSError) -> PeerIdentity?)? = nil
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

    /// A client configuration.
    public static func client(serverName: String? = nil, alpn: [String] = []) -> TLSConfiguration {
        TLSConfiguration(serverName: serverName, alpnProtocols: alpn)
    }

    /// A server configuration (requires identity material).
    public static func server(identity: TLSIdentity, alpn: [String] = []) -> TLSConfiguration {
        TLSConfiguration(alpnProtocols: alpn, identity: identity)
    }
}
