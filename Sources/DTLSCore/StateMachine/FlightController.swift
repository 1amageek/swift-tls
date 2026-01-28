/// DTLS Flight-based Retransmission Controller (RFC 6347 Section 4.2.4)
///
/// DTLS groups handshake messages into "flights" and retransmits the entire
/// flight if no response is received. Uses exponential backoff:
///   initial = 1 second, max = 60 seconds, factor = 2x

import Foundation
import Synchronization

/// DTLS flight identifier
public enum DTLSFlight: Sendable, Equatable {
    /// Client → Server: ClientHello (initial or with cookie)
    case clientHello

    /// Server → Client: HelloVerifyRequest
    case helloVerifyRequest

    /// Server → Client: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
    case serverHelloToCertDone

    /// Client → Server: Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished
    case clientKeyExchangeToFinished

    /// Server → Client: CCS, Finished
    case serverChangeCipherSpecFinished
}

/// Flight retransmission controller
public final class FlightController: Sendable {
    private let _state: Mutex<FlightState>

    /// Configuration
    private let initialTimeout: Duration = .seconds(1)
    private let maxTimeout: Duration = .seconds(60)
    private let maxRetransmissions: Int = 6

    private struct FlightState: Sendable {
        var currentFlight: DTLSFlight?
        var flightData: [Data] = []
        var retransmissionCount: Int = 0
        var currentTimeout: Duration = .seconds(1)
    }

    public init() {
        self._state = Mutex(FlightState())
    }

    /// Start a new flight with the given messages
    /// - Parameters:
    ///   - flight: The flight identifier
    ///   - messages: The encoded messages for this flight
    public func startFlight(_ flight: DTLSFlight, messages: [Data]) {
        _state.withLock { s in
            s.currentFlight = flight
            s.flightData = messages
            s.retransmissionCount = 0
            s.currentTimeout = initialTimeout
        }
    }

    /// Get the current flight's messages for retransmission
    /// - Returns: The flight messages, or nil if no active flight
    public func flightMessages() -> [Data]? {
        _state.withLock { s in
            guard s.currentFlight != nil else { return nil }
            return s.flightData
        }
    }

    /// Record that a response was received, canceling retransmission
    public func responseReceived() {
        _state.withLock { s in
            s.currentFlight = nil
            s.flightData = []
            s.retransmissionCount = 0
            s.currentTimeout = initialTimeout
        }
    }

    /// Check if retransmission is needed after timeout
    /// - Returns: Messages to retransmit
    /// - Throws: If max retransmissions exceeded
    public func retransmit() throws -> [Data] {
        try _state.withLock { s in
            guard s.currentFlight != nil else {
                throw DTLSError.invalidState("No active flight to retransmit")
            }

            s.retransmissionCount += 1
            if s.retransmissionCount > maxRetransmissions {
                throw DTLSError.maxRetransmissionsExceeded
            }

            // Exponential backoff
            let newTimeout = Duration.seconds(
                min(
                    s.currentTimeout.components.seconds * 2,
                    maxTimeout.components.seconds
                )
            )
            s.currentTimeout = newTimeout

            return s.flightData
        }
    }

    /// Get the current timeout duration
    public var timeout: Duration {
        _state.withLock { $0.currentTimeout }
    }

    /// Whether there is an active flight awaiting response
    public var isAwaitingResponse: Bool {
        _state.withLock { $0.currentFlight != nil }
    }

    /// The current retransmission count
    public var retransmissions: Int {
        _state.withLock { $0.retransmissionCount }
    }
}
