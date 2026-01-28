/// FlightController Contract Tests
///
/// Tests the retransmission control invariants:
/// A. Exponential backoff follows 1s → 2s → 4s → ... → 60s cap
/// B. Maximum retransmissions (6) are enforced
/// C. Flight lifecycle state transitions are correct

import Testing
import Foundation
@testable import DTLSCore

@Suite("FlightController Contract Tests")
struct FlightControllerContractTests {

    // MARK: - Contract A: Exponential Backoff

    @Test("Backoff doubles on each retransmission")
    func backoffDoublesOnEachRetransmission() throws {
        let fc = FlightController()
        fc.startFlight(.clientHello, messages: [Data([1])])

        let expectedSeconds: [Int64] = [2, 4, 8, 16, 32, 60]
        for (i, expected) in expectedSeconds.enumerated() {
            _ = try fc.retransmit()
            #expect(
                fc.timeout == .seconds(expected),
                "After retransmission \(i + 1), timeout should be \(expected)s"
            )
        }
    }

    @Test("Backoff caps at 60 seconds, not 64")
    func backoffCapsAtSixtySeconds() throws {
        let fc = FlightController()
        fc.startFlight(.clientHello, messages: [Data([1])])

        // 5 retransmissions: 2, 4, 8, 16, 32
        for _ in 0..<5 {
            _ = try fc.retransmit()
        }
        #expect(fc.timeout == .seconds(32))

        // 6th retransmission: should be 60 (capped), not 64
        _ = try fc.retransmit()
        #expect(fc.timeout == .seconds(60))
    }

    @Test("Initial timeout is 1 second")
    func initialTimeoutIsOneSecond() {
        let fc = FlightController()
        fc.startFlight(.clientHello, messages: [Data([1])])

        #expect(fc.timeout == .seconds(1))
    }

    // MARK: - Contract B: Maximum Retransmissions

    @Test("7th retransmission throws maxRetransmissionsExceeded")
    func maxRetransmissionsThrowsAfterSixAttempts() throws {
        let fc = FlightController()
        fc.startFlight(.clientHello, messages: [Data([1])])

        // 6 retransmissions succeed
        for _ in 0..<6 {
            _ = try fc.retransmit()
        }

        // 7th throws
        #expect(throws: DTLSError.self) {
            _ = try fc.retransmit()
        }
    }

    @Test("Retransmit with no active flight throws")
    func retransmitWithNoActiveFlightThrows() {
        let fc = FlightController()

        #expect(throws: DTLSError.self) {
            _ = try fc.retransmit()
        }
    }

    // MARK: - Contract C: Flight Lifecycle

    @Test("startFlight activates awaiting response")
    func startFlightActivatesAwaitingResponse() {
        let fc = FlightController()
        let testData = Data("test flight".utf8)

        fc.startFlight(.clientHello, messages: [testData])

        #expect(fc.isAwaitingResponse)
        #expect(fc.flightMessages() == [testData])
    }

    @Test("responseReceived clears all state")
    func responseReceivedClearsAllState() throws {
        let fc = FlightController()
        fc.startFlight(.clientHello, messages: [Data([1])])

        // Advance retransmission state
        _ = try fc.retransmit()
        _ = try fc.retransmit()
        #expect(fc.retransmissions == 2)

        // Receive response
        fc.responseReceived()

        #expect(!fc.isAwaitingResponse)
        #expect(fc.flightMessages() == nil)
        #expect(fc.retransmissions == 0)
        #expect(fc.timeout == .seconds(1))
    }

    @Test("Starting new flight resets retransmission count")
    func startNewFlightResetsRetransmissionCount() throws {
        let fc = FlightController()

        // First flight with retransmissions
        fc.startFlight(.clientHello, messages: [Data([1])])
        _ = try fc.retransmit()
        _ = try fc.retransmit()
        _ = try fc.retransmit()
        #expect(fc.retransmissions == 3)

        // Start new flight — should reset
        fc.startFlight(.serverHelloToCertDone, messages: [Data([2])])

        #expect(fc.retransmissions == 0)
        #expect(fc.timeout == .seconds(1))
    }

    @Test("Retransmit returns original flight data")
    func retransmitReturnsOriginalFlightData() throws {
        let fc = FlightController()
        let data1 = Data("message 1".utf8)
        let data2 = Data("message 2".utf8)

        fc.startFlight(.clientKeyExchangeToFinished, messages: [data1, data2])

        let retransmitted = try fc.retransmit()
        #expect(retransmitted == [data1, data2])
    }
}
