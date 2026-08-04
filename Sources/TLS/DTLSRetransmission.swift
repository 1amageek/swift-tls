import SSLDTLS

/// Caller-owned timer token for a DTLS handshake flight.
///
/// Schedule one timeout for `nextDelay`. When it fires, pass `generation` to
/// `handleTimeout(generation:)`. A nil delay means no timer should be scheduled.
public struct DTLSRetransmissionState: Sendable, Equatable {
    public let generation: UInt64
    public let nextDelay: Duration?

    public init(generation: UInt64, nextDelay: Duration?) {
        self.generation = generation
        self.nextDelay = nextDelay
    }

    init(engine: DTLSEngineRetransmissionState) {
        self.init(generation: engine.generation, nextDelay: engine.nextDelay)
    }
}

/// Generation-aware result of one DTLS flight timeout.
public enum DTLSTimeoutResult: Sendable, Equatable {
    /// A current timer re-encoded the retained flight with fresh record sequence
    /// numbers. Replace the timer with `next`.
    case retransmit(datagrams: [[UInt8]], next: DTLSRetransmissionState)

    /// The timer was stale or no timed flight remains. No bytes were emitted.
    case superseded(current: DTLSRetransmissionState)

    init(engine: DTLSEngineTimeoutResult) {
        switch engine {
        case .retransmit(let datagrams, let next):
            self = .retransmit(
                datagrams: datagrams,
                next: DTLSRetransmissionState(engine: next)
            )
        case .superseded(let current):
            self = .superseded(current: DTLSRetransmissionState(engine: current))
        }
    }
}
