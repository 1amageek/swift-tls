/// A concrete, application-defined peer identity established during the handshake.
///
/// Replaces the old `validatedPeerInfo: (any Sendable)?` existential. The custom
/// certificate validator returns a `PeerIdentity` (e.g. a libp2p PeerID carried in
/// the certificate extension); the facade surfaces it as `peerIdentity` after the
/// handshake completes. Modelled as a value type holding the application-specific
/// identifier bytes plus the peer's leaf certificate.
public struct PeerIdentity: Sendable, Hashable {
    /// Application-specific identifier bytes (e.g. an encoded libp2p PeerID).
    /// Empty when the validator established trust without producing an identifier.
    public let identifier: [UInt8]

    /// The peer's certificate chain (leaf first) as presented in the handshake.
    public let certificates: [Certificate]

    public init(identifier: [UInt8] = [], certificates: [Certificate] = []) {
        self.identifier = identifier
        self.certificates = certificates
    }
}
