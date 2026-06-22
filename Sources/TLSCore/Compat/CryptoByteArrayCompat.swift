/// `[UInt8]`-accepting overloads for the adapter's `Data`-based crypto helpers.
///
/// The Embedded-clean wire types now expose byte fields as `[UInt8]`. Existing
/// callers (and tests) feed those fields straight into `Data`-based crypto
/// helpers; these overloads accept `[UInt8]` and forward to the `Data` form so
/// no call site needs an explicit conversion.

import Foundation
import Crypto

extension TLSKeySchedule {
    /// `[UInt8]` overload of ``deriveResumptionPSK(resumptionMasterSecret:ticketNonce:)``.
    public func deriveResumptionPSK(
        resumptionMasterSecret: SymmetricKey,
        ticketNonce: [UInt8]
    ) -> SymmetricKey {
        deriveResumptionPSK(
            resumptionMasterSecret: resumptionMasterSecret,
            ticketNonce: Data(ticketNonce)
        )
    }
}

extension SessionTicketData {
    /// `[UInt8]` overload of the ticket-bytes initializer.
    public init(
        ticket: [UInt8],
        resumptionPSK: SymmetricKey,
        maxEarlyDataSize: UInt32 = 0,
        ticketAgeAdd: UInt32,
        receiveTime: Date = Date(),
        lifetime: UInt32,
        cipherSuite: CipherSuite,
        serverName: String? = nil,
        alpn: String? = nil
    ) {
        self.init(
            ticket: Data(ticket),
            resumptionPSK: resumptionPSK,
            maxEarlyDataSize: maxEarlyDataSize,
            ticketAgeAdd: ticketAgeAdd,
            receiveTime: receiveTime,
            lifetime: lifetime,
            cipherSuite: cipherSuite,
            serverName: serverName,
            alpn: alpn
        )
    }
}
