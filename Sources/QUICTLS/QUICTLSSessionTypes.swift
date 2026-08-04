import SSLQUIC
import SSLTLS

/// The only input levels accepted by the QUIC TLS session boundary.
public typealias QUICTLSHandshakeInputLevel = SSLQUIC.QUICTLSHandshakeInputLevel

/// Output batch whose bytes are borrowed through a scoped closure and whose
/// effects consume traffic-secret owners exactly once.
public typealias QUICTLSStepOutput = SSLQUIC.QUICTLSStepOutput
public typealias QUICTLSEffect = SSLQUIC.QUICTLSEffect
public typealias QUICTLSAction = SSLQUIC.QUICTLSAction
public typealias QUICHandshakeEncryptionLevel = SSLQUIC.QUICHandshakeEncryptionLevel
public typealias QUICTLSClientHandshake = SSLQUIC.QUICTLSClientHandshake
public typealias QUICTLSServerHandshake = SSLQUIC.QUICTLSServerHandshake

public typealias QUICTLSHandshakeTransition = SSLQUIC.QUICTLSHandshakeTransition
public typealias QUICTLSHandshakeError = SSLQUIC.QUICTLSHandshakeError
public typealias TLS13ApplicationProtocol = SSLTLS.TLS13ApplicationProtocol
public typealias TLS13CapabilityResponse = SSLTLS.TLS13CapabilityResponse
public typealias QUICSecretDirection = SSLQUIC.QUICSecretDirection
public typealias QUICTrafficSecretEvent = SSLQUIC.QUICTrafficSecretEvent
