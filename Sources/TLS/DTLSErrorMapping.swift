/// Maps the cored DTLS engine error onto the single public `TLSError`.
///
/// The DTLS facade folds `DTLSEngineCore.DTLSEngineError` into the one public
/// `TLSError` (the same surface the TLS facade uses), so a caller has exactly one
/// exhaustive `catch`. Nothing is silently swallowed — every verification, cookie,
/// replay, or protocol failure preserves its category.

import DTLSEngineCore

extension TLSError {
    /// Folds the cored DTLS engine's typed error onto the facade `TLSError`,
    /// preserving the failure category (verification failures stay verification
    /// failures — never collapsed to a generic protocol error or success).
    static func fromDTLSEngine(_ e: DTLSEngineError) -> TLSError {
        switch e {
        case .handshakeNotStarted:
            return .internalError(reason: "DTLS handshake not started")
        case .handshakeNotComplete:
            return .handshakeNotComplete
        case .handshakeAlreadyStarted:
            return .internalError(reason: "DTLS handshake already started")
        case .connectionClosed:
            return .connectionClosed
        case .protocolFailure(let reason):
            return .protocolFailure(reason: reason)
        case .fatalAlert(let code, let reason):
            return .fatalAlert(code: code, reason: reason)
        case .verificationFailed(let reason):
            return .verificationFailed(reason: reason)
        case .invalidConfiguration(let reason):
            return .invalidConfiguration(reason: reason)
        case .bufferOverflow:
            return .bufferOverflow
        case .maxRetransmissionsExceeded:
            return .protocolFailure(reason: "DTLS maximum retransmissions exceeded")
        case .internalError(let reason):
            return .internalError(reason: reason)
        }
    }
}
