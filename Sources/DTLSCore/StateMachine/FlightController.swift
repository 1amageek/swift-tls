/// DTLS Flight-based Retransmission Controller (RFC 6347 Section 4.2.4)
///
/// DTLS groups handshake messages into "flights" and retransmits the entire
/// flight if no response is received. Uses exponential backoff:
///   initial = 1 second, max = 60 seconds, factor = 2x

import Foundation

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
public actor FlightController {
    /// Current flight data (messages to retransmit)
    private var currentFlight: DTLSFlight?
    private var flightData: [Data] = []

    /// Retransmission state
    private var retransmissionCount: Int = 0
    private var currentTimeout: Duration = .seconds(1)

    /// Configuration
    private let initialTimeout: Duration = .seconds(1)
    private let maxTimeout: Duration = .seconds(60)
    private let maxRetransmissions: Int = 6

    public init() {}

    /// Start a new flight with the given messages
    /// - Parameters:
    ///   - flight: The flight identifier
    ///   - messages: The encoded messages for this flight
    public func startFlight(_ flight: DTLSFlight, messages: [Data]) {
        currentFlight = flight
        flightData = messages
        retransmissionCount = 0
        currentTimeout = initialTimeout
    }

    /// Get the current flight's messages for retransmission
    /// - Returns: The flight messages, or nil if no active flight
    public func flightMessages() -> [Data]? {
        guard currentFlight != nil else { return nil }
        return flightData
    }

    /// Record that a response was received, canceling retransmission
    public func responseReceived() {
        currentFlight = nil
        flightData = []
        retransmissionCount = 0
        currentTimeout = initialTimeout
    }

    /// Check if retransmission is needed after timeout
    /// - Returns: Messages to retransmit
    /// - Throws: If max retransmissions exceeded
    public func retransmit() throws -> [Data] {
        guard let _ = currentFlight else {
            throw DTLSError.invalidState("No active flight to retransmit")
        }

        retransmissionCount += 1
        if retransmissionCount > maxRetransmissions {
            throw DTLSError.maxRetransmissionsExceeded
        }

        // Exponential backoff
        let newTimeout = Duration.seconds(
            min(
                currentTimeout.components.seconds * 2,
                maxTimeout.components.seconds
            )
        )
        currentTimeout = newTimeout

        return flightData
    }

    /// Get the current timeout duration
    public var timeout: Duration {
        currentTimeout
    }

    /// Whether there is an active flight awaiting response
    public var isAwaitingResponse: Bool {
        currentFlight != nil
    }

    /// The current retransmission count
    public var retransmissions: Int {
        retransmissionCount
    }
}
