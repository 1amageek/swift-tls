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

extension TLSError {
    /// Folds any engine error thrown by the TLS byte-stream engine into `TLSError`.
    static func from(_ error: any Error) -> TLSError {
        switch error {
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
