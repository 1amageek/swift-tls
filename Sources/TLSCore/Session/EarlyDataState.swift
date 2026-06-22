/// State tracking for 0-RTT early data.
///
/// Holds the client early traffic secret (`SymmetricKey`), so it depends on
/// Crypto and stays in the `TLSCore` adapter (the pure `EarlyDataExtension`
/// wire type lives in `TLSWireCore`).

import Foundation
import Crypto

// MARK: - Early Data State

/// State tracking for 0-RTT early data
public struct EarlyDataState: Sendable {
    /// Whether early data is being attempted
    public var attemptingEarlyData: Bool = false

    /// Whether server accepted early data
    public var earlyDataAccepted: Bool = false

    /// Maximum early data size from ticket
    public var maxEarlyDataSize: UInt32 = 0

    /// Amount of early data sent
    public var earlyDataSent: UInt32 = 0

    /// Client early traffic secret (for 0-RTT encryption)
    public var clientEarlyTrafficSecret: SymmetricKey?

    public init() {}

    /// Check if more early data can be sent
    public var canSendMoreEarlyData: Bool {
        guard attemptingEarlyData else { return false }
        guard maxEarlyDataSize > 0 else { return false }
        return earlyDataSent < maxEarlyDataSize
    }

    /// Record early data being sent
    public mutating func recordEarlyData(size: UInt32) {
        earlyDataSent = earlyDataSent.addingReportingOverflow(size).partialValue
    }
}
