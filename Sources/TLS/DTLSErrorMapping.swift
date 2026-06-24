/// Maps the DTLS engine error/anomaly types onto the public `TLSError`/`DTLSOutput`.
///
/// The DTLS facade folds `DTLSConnectionError` into the single public `TLSError`,
/// and translates the engine's `DTLSRecordAnomaly` into `DTLSOutput.Anomaly`.
/// Nothing is silently swallowed.

import DTLSCore
import DTLSRecord

extension TLSError {
    /// Folds a DTLS engine error into `TLSError`.
    static func fromDTLS(_ error: any Error) -> TLSError {
        switch error {
        case let e as DTLSConnectionError:
            switch e {
            case .handshakeNotStarted:
                return .internalError(reason: "DTLS handshake not started")
            case .handshakeNotComplete:
                return .handshakeNotComplete
            case .handshakeAlreadyStarted:
                return .internalError(reason: "DTLS handshake already started")
            case .connectionClosed:
                return .connectionClosed
            case .fatalProtocolError(let reason):
                return .protocolFailure(reason: reason)
            }
        case let e as TLSError:
            return e
        default:
            return .internalError(reason: String(describing: error))
        }
    }
}

extension DTLSOutput.Anomaly {
    /// Translate an engine record anomaly to the facade anomaly.
    static func from(_ anomaly: DTLSRecordAnomaly) -> DTLSOutput.Anomaly {
        switch anomaly {
        case .authenticationFailed: return .authenticationFailed
        case .malformed:            return .malformed
        case .replayed:             return .replayed
        case .tooOld:               return .tooOld
        case .malformedAlert:       return .malformedAlert
        }
    }
}
