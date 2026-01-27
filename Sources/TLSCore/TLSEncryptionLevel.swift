/// TLS encryption levels for key material delivery.
///
/// Encryption levels for TLS 1.3 handshake phases.
public enum TLSEncryptionLevel: Int, Sendable, Hashable, CaseIterable {
    /// Initial handshake (ClientHello/ServerHello)
    case initial = 0
    /// Early data (0-RTT)
    case earlyData = 1
    /// Handshake encryption
    case handshake = 2
    /// Application data encryption
    case application = 3
}
