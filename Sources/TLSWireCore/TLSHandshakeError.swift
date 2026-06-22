/// TLS 1.3 handshake error type (RFC 8446).
///
/// Shared by the wire codecs (which throw `.invalidExtension`/`.decodeError`)
/// and the handshake state machine in the `TLSCore` adapter. Pure value type
/// with no Foundation dependency.

/// Errors raised during TLS 1.3 handshake processing.
public enum TLSHandshakeError: Error, Sendable, Equatable {
    /// Unexpected message in current state
    case unexpectedMessage(String)

    /// Protocol version mismatch
    case unsupportedVersion

    /// RFC 8446 §4.1.3: a TLS version downgrade was detected via the ServerHello
    /// random downgrade sentinel.
    case downgradeDetected

    /// No common cipher suite
    case noCipherSuiteMatch

    /// No common named group for key exchange
    case noKeyShareMatch

    /// No common ALPN protocol
    case noALPNMatch

    /// Certificate verification failed
    case certificateVerificationFailed(String)

    /// Signature verification failed
    case signatureVerificationFailed

    /// Finished message verification failed
    case finishedVerificationFailed

    /// Missing required extension
    case missingExtension(String)

    /// Invalid extension
    case invalidExtension(String)

    /// Key exchange failed
    case keyExchangeFailed(String)

    /// Decryption failed
    case decryptionFailed

    /// Internal error
    case internalError(String)

    /// Client certificate required but not provided
    case certificateRequired

    /// No common certificate type, or peer used a type that was not
    /// negotiated (RFC 7250)
    case unsupportedCertificateType(String)

    /// Decode error (malformed message)
    case decodeError(String)

    public static func == (lhs: TLSHandshakeError, rhs: TLSHandshakeError) -> Bool {
        switch (lhs, rhs) {
        case (.unexpectedMessage(let l), .unexpectedMessage(let r)): return l == r
        case (.unsupportedVersion, .unsupportedVersion): return true
        case (.downgradeDetected, .downgradeDetected): return true
        case (.noCipherSuiteMatch, .noCipherSuiteMatch): return true
        case (.noKeyShareMatch, .noKeyShareMatch): return true
        case (.noALPNMatch, .noALPNMatch): return true
        case (.certificateVerificationFailed(let l), .certificateVerificationFailed(let r)): return l == r
        case (.signatureVerificationFailed, .signatureVerificationFailed): return true
        case (.finishedVerificationFailed, .finishedVerificationFailed): return true
        case (.missingExtension(let l), .missingExtension(let r)): return l == r
        case (.invalidExtension(let l), .invalidExtension(let r)): return l == r
        case (.keyExchangeFailed(let l), .keyExchangeFailed(let r)): return l == r
        case (.decryptionFailed, .decryptionFailed): return true
        case (.internalError(let l), .internalError(let r)): return l == r
        case (.certificateRequired, .certificateRequired): return true
        case (.unsupportedCertificateType(let l), .unsupportedCertificateType(let r)): return l == r
        case (.decodeError(let l), .decodeError(let r)): return l == r
        default: return false
        }
    }

    /// Convert this error to a TLS Alert for sending to the peer
    public var toAlert: TLSAlert {
        switch self {
        case .unexpectedMessage:
            return TLSAlert(description: .unexpectedMessage)
        case .unsupportedVersion:
            return TLSAlert(description: .protocolVersion)
        case .downgradeDetected:
            // RFC 8446 §4.1.3: abort with illegal_parameter on a detected downgrade.
            return TLSAlert(description: .illegalParameter)
        case .noCipherSuiteMatch:
            return TLSAlert(description: .handshakeFailure)
        case .noKeyShareMatch:
            return TLSAlert(description: .handshakeFailure)
        case .noALPNMatch:
            return TLSAlert(description: .noApplicationProtocol)
        case .certificateVerificationFailed:
            return TLSAlert(description: .badCertificate)
        case .signatureVerificationFailed:
            return TLSAlert(description: .decryptError)
        case .finishedVerificationFailed:
            return TLSAlert(description: .decryptError)
        case .missingExtension:
            return TLSAlert(description: .missingExtension)
        case .invalidExtension:
            return TLSAlert(description: .illegalParameter)
        case .keyExchangeFailed:
            return TLSAlert(description: .handshakeFailure)
        case .decryptionFailed:
            return TLSAlert(description: .decryptError)
        case .internalError:
            return TLSAlert(description: .internalError)
        case .certificateRequired:
            return TLSAlert(description: .certificateRequired)
        case .unsupportedCertificateType:
            return TLSAlert(description: .unsupportedCertificate)
        case .decodeError:
            return TLSAlert(description: .decodeError)
        }
    }
}
