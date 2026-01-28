/// DTLS 1.2 Server State Machine
///
/// Tracks the server's progress through the DTLS handshake:
///   idle → waitingClientHelloWithCookie → waitingClientKeyExchange
///   → waitingChangeCipherSpec → waitingFinished → connected

import Foundation
import TLSCore

/// Server handshake state
public enum DTLSServerState: Sendable, Equatable {
    /// Initial state
    case idle

    /// Sent HelloVerifyRequest, waiting for ClientHello with cookie
    case waitingClientHelloWithCookie

    /// Received valid ClientHello, sent server flight, waiting for client response
    case waitingClientKeyExchange

    /// Waiting for client CCS
    case waitingChangeCipherSpec

    /// Waiting for client Finished
    case waitingFinished

    /// Handshake complete
    case connected

    /// Error state
    case failed(String)
}

/// Server handshake context
public struct DTLSServerContext: Sendable {
    /// Client random
    public var clientRandom: Data?

    /// Our server random
    public var serverRandom: Data?

    /// Selected cipher suite
    public var cipherSuite: DTLSCipherSuite?

    /// Client's certificate (DER), if mutual auth
    public var clientCertificateDER: Data?

    /// Client's ECDHE public key
    public var clientPublicKey: Data?

    /// Our ECDHE key pair
    public var keyExchange: KeyExchange?

    /// Cookie secret for HelloVerifyRequest
    public var cookieSecret: Data?

    /// Current message sequence number
    public var messageSeq: UInt16 = 0

    /// Key schedule
    public var keySchedule: DTLSKeySchedule?

    /// Accumulated handshake message bytes for transcript hash
    public var handshakeMessages: Data = Data()

    public init() {}

    /// Get the next message sequence number and increment
    public mutating func nextMessageSeq() -> UInt16 {
        let seq = messageSeq
        messageSeq += 1
        return seq
    }
}
