/// A server-emitted TLS 1.3 NewSessionTicket and the state needed to accept it.
public struct TLSIssuedSessionTicket: Sendable {
    public let bytesToSend: [UInt8]
    public let resumptionState: TLSResumptionState

    init(bytesToSend: [UInt8], resumptionState: TLSResumptionState) {
        self.bytesToSend = bytesToSend
        self.resumptionState = resumptionState
    }
}
