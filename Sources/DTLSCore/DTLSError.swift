/// DTLS Error Types

import Foundation

/// Errors that occur during DTLS operations
public enum DTLSError: Error, Sendable {
    // Handshake errors
    case unexpectedMessage(expected: DTLSHandshakeType, received: DTLSHandshakeType)
    case handshakeFailed(String)
    case invalidState(String)
    case timeout

    // Cipher suite
    case unsupportedCipherSuite(UInt16)
    case noCipherSuiteMatch

    // Certificate
    case certificateGenerationFailed(String)
    case invalidCertificate(String)
    case fingerprintMismatch

    // Key exchange
    case keyExchangeFailed(String)
    case invalidServerKeyExchange(String)

    // Cookie
    case invalidCookie
    case cookieMismatch

    // Message format
    case invalidFormat(String)
    case insufficientData(expected: Int, actual: Int)
    case fragmentationNotSupported

    // Verify
    case verifyDataMismatch
    case signatureVerificationFailed

    // Flight / retransmission
    case maxRetransmissionsExceeded
    case flightTimeout
}

extension DTLSError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unexpectedMessage(let expected, let received):
            return "Unexpected message: expected \(expected), received \(received)"
        case .handshakeFailed(let reason):
            return "Handshake failed: \(reason)"
        case .invalidState(let state):
            return "Invalid state: \(state)"
        case .timeout:
            return "DTLS timeout"
        case .unsupportedCipherSuite(let value):
            return "Unsupported cipher suite: 0x\(String(value, radix: 16))"
        case .noCipherSuiteMatch:
            return "No matching cipher suite"
        case .certificateGenerationFailed(let reason):
            return "Certificate generation failed: \(reason)"
        case .invalidCertificate(let reason):
            return "Invalid certificate: \(reason)"
        case .fingerprintMismatch:
            return "Certificate fingerprint mismatch"
        case .keyExchangeFailed(let reason):
            return "Key exchange failed: \(reason)"
        case .invalidServerKeyExchange(let reason):
            return "Invalid ServerKeyExchange: \(reason)"
        case .invalidCookie:
            return "Invalid DTLS cookie"
        case .cookieMismatch:
            return "Cookie mismatch"
        case .invalidFormat(let reason):
            return "Invalid format: \(reason)"
        case .insufficientData(let expected, let actual):
            return "Insufficient data: expected \(expected) bytes, got \(actual)"
        case .fragmentationNotSupported:
            return "Handshake fragmentation not supported"
        case .verifyDataMismatch:
            return "Verify data mismatch"
        case .signatureVerificationFailed:
            return "Signature verification failed"
        case .maxRetransmissionsExceeded:
            return "Maximum retransmissions exceeded"
        case .flightTimeout:
            return "Flight timeout"
        }
    }
}
