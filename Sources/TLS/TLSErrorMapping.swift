/// Maps the engine-level error types onto the single public `TLSError`.
///
/// The record/handshake engines (`TLSConnection`, `TLS13Handler`, and their
/// underlying codec cores) throw a family of implementation-level error enums.
/// The facade catches them at its boundary and folds them into `TLSError` so the
/// public surface has exactly one error type. Unknown errors are surfaced as
/// `.internalError` with a description — never silently swallowed.

import TLSCore
import TLSRecord
import TLSWireCore
import TLSRecordCore
import TLSEngineCore

extension TLSError {
    /// Folds the cored engine's typed error onto the facade `TLSError`, preserving
    /// the failure category (verification failures stay verification failures —
    /// never collapsed to a generic protocol error or, worse, success).
    static func fromEngine(_ e: TLSEngineCore.TLSEngineError) -> TLSError {
        switch e {
        case .handshakeNotComplete:
            return .handshakeNotComplete
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
        case .internalError(let reason):
            return .internalError(reason: reason)
        }
    }

    /// Folds any engine error thrown by the TLS byte-stream engine into `TLSError`.
    static func from(_ error: any Error) -> TLSError {
        switch error {
        case let e as TLSEngineCore.TLSEngineError:
            return fromEngine(e)
        case let e as TLSConnectionError:
            return from(e)
        case let e as TLSHandshakeError:
            return .protocolFailure(reason: String(describing: e))
        case let e as TLSRecordError:
            return .protocolFailure(reason: String(describing: e))
        case let e as TLSCore.TLSError:
            return from(e)
        case let e as TLSConfigurationError:
            return .invalidConfiguration(reason: String(describing: e))
        case let e as TLSError:
            // Already the facade type (e.g. re-thrown from configuration build).
            return e
        default:
            return .internalError(reason: String(describing: error))
        }
    }

    private static func from(_ e: TLSConnectionError) -> TLSError {
        switch e {
        case .handshakeNotComplete:
            return .handshakeNotComplete
        case .connectionClosed:
            return .connectionClosed
        case .bufferOverflow:
            return .bufferOverflow
        case .concurrentReadNotAllowed:
            return .concurrentReceiveNotAllowed
        case .fatalAlert(let alert):
            return .fatalAlert(
                code: alert.alertDescription.rawValue,
                reason: alert.description
            )
        case .fatalProtocolError(let kind):
            return .protocolFailure(reason: kind.description)
        }
    }

    private static func from(_ e: TLSCore.TLSError) -> TLSError {
        switch e {
        case .certificateVerificationFailed(let reason):
            return .verificationFailed(reason: reason)
        case .handshakeFailed(_, let description):
            return .protocolFailure(reason: description)
        case .noCipherSuiteMatch, .noALPNMatch, .unexpectedMessage,
             .invalidTransportParameters:
            return .protocolFailure(reason: String(describing: e))
        case .internalError(let reason):
            return .internalError(reason: reason)
        }
    }
}
