/// Stored session ticket for resumption.
///
/// Carries the resumption PSK (`SymmetricKey`) and receive `Date`, so it depends
/// on Crypto/Foundation and stays in the `TLSCore` adapter (the pure
/// `NewSessionTicket` wire message lives in `TLSWireCore`).

import Foundation
import TLSWireCore
import Crypto

// MARK: - Session Ticket Data

/// Stored session ticket for resumption
public struct SessionTicketData: Sendable {
    /// The ticket value to send to server
    public let ticket: Data

    /// Resumption PSK derived from resumption_master_secret
    public let resumptionPSK: SymmetricKey

    /// Maximum early data size (0 if not supported)
    public let maxEarlyDataSize: UInt32

    /// Ticket age add value (for obfuscation)
    public let ticketAgeAdd: UInt32

    /// Time when ticket was received
    public let receiveTime: Date

    /// Ticket lifetime in seconds
    public let lifetime: UInt32

    /// The cipher suite used in the original connection
    public let cipherSuite: CipherSuite

    /// Server name for this ticket (for matching)
    public let serverName: String?

    /// ALPN protocol used
    public let alpn: String?

    // MARK: - Initialization

    public init(
        ticket: Data,
        resumptionPSK: SymmetricKey,
        maxEarlyDataSize: UInt32 = 0,
        ticketAgeAdd: UInt32,
        receiveTime: Date = Date(),
        lifetime: UInt32,
        cipherSuite: CipherSuite,
        serverName: String? = nil,
        alpn: String? = nil
    ) {
        self.ticket = ticket
        self.resumptionPSK = resumptionPSK
        self.maxEarlyDataSize = maxEarlyDataSize
        self.ticketAgeAdd = ticketAgeAdd
        self.receiveTime = receiveTime
        self.lifetime = lifetime
        self.cipherSuite = cipherSuite
        self.serverName = serverName
        self.alpn = alpn
    }

    // MARK: - Validity

    /// Check if the ticket is still valid
    public func isValid(at date: Date = Date()) -> Bool {
        let elapsed = date.timeIntervalSince(receiveTime)
        return elapsed >= 0 && elapsed < Double(lifetime)
    }

    /// Get obfuscated ticket age for pre_shared_key extension
    /// - Parameter now: Current time
    /// - Returns: Obfuscated age in milliseconds
    public func obfuscatedAge(at now: Date = Date()) -> UInt32 {
        let ageMs = UInt32(now.timeIntervalSince(receiveTime) * 1000)
        // Add ticketAgeAdd with wrapping to obfuscate
        return ageMs &+ ticketAgeAdd
    }
}
