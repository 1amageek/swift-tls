/// Maps the cored DTLS engine error onto the single public `TLSError`.
///
/// The DTLS facade folds the swift-ssl engine error into the one public
/// `TLSError` (the same surface the TLS facade uses), so a caller has exactly one
/// exhaustive `catch`. Nothing is silently swallowed — every verification, cookie,
/// replay, or protocol failure preserves its category.

import SSLDTLS

extension TLSError {
    /// Folds the cored DTLS engine's typed error onto the facade `TLSError`,
    /// preserving the failure category (verification failures stay verification
    /// failures — never collapsed to a generic protocol error or success).
    static func fromDTLSEngine(_ e: DTLSEngineError) -> TLSError {
        switch e {
        case .handshakeNotStarted:
            return .handshakeNotComplete
        case .handshakeNotComplete:
            return .handshakeNotComplete
        case .handshakeAlreadyStarted:
            return .protocolFailure(reason: "DTLS handshake already started")
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
            return .retransmissionLimitExceeded
        case .internalError(let reason):
            return .internalError(reason: reason)
        }
    }

    /// Maps the existential error emitted by a throwing lock closure without
    /// relying on `Result.mapError`'s generic reabstraction path. The closure's
    /// contract only permits `DTLSEngineError`; the explicit fallback preserves
    /// that invariant as a typed internal failure if a future implementation
    /// violates it instead of turning an unexpected error into success.
    static func fromDTLSEngine(_ error: any Error) -> TLSError {
        guard let engineError = error as? DTLSEngineError else {
            return .internalError(reason: "Unexpected DTLS engine error")
        }
        return fromDTLSEngine(engineError)
    }
}
