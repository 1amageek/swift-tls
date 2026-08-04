import SSLCore
import SSLQUIC

/// Public QUIC TLS server session boundary.
///
/// QUIC owns CRYPTO offsets and reassembly. This value receives one complete
/// handshake message at a time and delegates all TLS semantics to swift-ssl.
public struct QUICTLSServerSession: ~Copyable, Sendable {
    private var handshake: QUICTLSServerHandshake

    public init(handshake: consuming QUICTLSServerHandshake) {
        self.handshake = consume handshake
    }

    public var isEstablished: Bool { handshake.isEstablished }

    public var negotiatedApplicationProtocol: TLS13ApplicationProtocol? {
        handshake.negotiatedApplicationProtocol
    }

    public var receivedTransportParameters: OwnedBytes? {
        handshake.receivedTransportParameters
    }

    public mutating func configureTransportParameters(
        _ parameters: Span<UInt8>
    ) throws(QUICTLSHandshakeError) {
        try handshake.configureTransportParameters(parameters)
    }

    public mutating func receive(
        _ message: Span<UInt8>,
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSStepOutput {
        try handshake.processHandshakeMessage(message, at: level)
    }

    public mutating func receiveStep(
        _ message: Span<UInt8>,
        at level: QUICTLSHandshakeInputLevel
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition {
        try handshake.processHandshakeMessageStep(message, at: level)
    }

    public mutating func resume(
        _ response: TLS13CapabilityResponse
    ) throws(QUICTLSHandshakeError) -> QUICTLSHandshakeTransition {
        try handshake.resume(response)
    }

    public mutating func updateOneRTTTrafficSecret(
        for direction: QUICSecretDirection
    ) throws(QUICTLSHandshakeError) -> QUICTrafficSecretEvent {
        try handshake.updateOneRTTTrafficSecret(for: direction)
    }
}
