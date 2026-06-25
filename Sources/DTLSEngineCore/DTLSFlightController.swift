/// The Embedded-clean, value-type DTLS flight retransmission controller
/// (RFC 6347 §4.2.4).
///
/// `DTLSFlightController` is the cored, caller-locked replacement for the host
/// `FlightController` (`Mutex` + `Duration`/`ContinuousClock`). The KEY Embedded
/// unblock: it holds NO clock and runs NO timer. The facade owns the timer and
/// calls ``retransmit()`` from the engine's `handleTimeout()`; this controller only
/// remembers the last flight bytes and the retransmission count, enforcing the
/// retransmission cap. Exponential-backoff *timing* is the facade's concern (the
/// host facade keeps the 1s→60s schedule); the controller bounds the COUNT.
///
/// DTLS groups handshake messages into flights and retransmits the WHOLE last
/// flight on a timeout, so the controller stores the most recently sent flight
/// (the datagrams) and clears it when a response arrives.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.
struct DTLSFlightController: Sendable {

    /// Maximum number of retransmissions before the handshake is abandoned.
    static var maxRetransmissions: Int { 6 }

    /// The datagrams of the last flight we sent (empty when idle / acknowledged).
    private var flightDatagrams: [[UInt8]] = []
    private var retransmissionCount: Int = 0
    private var awaitingResponse: Bool = false

    init() {}

    /// Whether a flight is awaiting a response (a retransmission could fire).
    var isAwaitingResponse: Bool { awaitingResponse }

    /// Registers a new flight for retransmission, resetting the count.
    mutating func startFlight(_ datagrams: [[UInt8]]) {
        guard !datagrams.isEmpty else { return }
        flightDatagrams = datagrams
        retransmissionCount = 0
        awaitingResponse = true
    }

    /// Cancels the pending retransmission when any datagram is received.
    mutating func responseReceived() {
        flightDatagrams = []
        retransmissionCount = 0
        awaitingResponse = false
    }

    /// Returns the last flight to retransmit, bumping the count. Throws once the
    /// retransmission cap is reached (no silent give-up). Returns `[]` when there
    /// is no active flight (a timeout with nothing pending is a no-op).
    mutating func retransmit() throws(DTLSEngineError) -> [[UInt8]] {
        guard awaitingResponse, !flightDatagrams.isEmpty else { return [] }
        retransmissionCount += 1
        if retransmissionCount > Self.maxRetransmissions {
            throw .maxRetransmissionsExceeded
        }
        return flightDatagrams
    }
}
