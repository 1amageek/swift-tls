/// DTLS 1.2 Server State Machine
///
/// Tracks the server's progress through the DTLS handshake:
///   idle → waitingClientHelloWithCookie → waitingClientKeyExchange
///   → waitingChangeCipherSpec → waitingFinished → connected

import Foundation
import TLSCore
import DTLSHandshakeCore

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

    /// Bridge from the Embedded-clean FSM state.
    init(core: DTLSServerHandshake<TLSProvider>.ServerState) {
        switch core {
        case .idle: self = .idle
        case .waitingClientHelloWithCookie: self = .waitingClientHelloWithCookie
        case .waitingClientKeyExchange: self = .waitingClientKeyExchange
        case .waitingChangeCipherSpec: self = .waitingChangeCipherSpec
        case .waitingFinished: self = .waitingFinished
        case .connected: self = .connected
        }
    }
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

    /// Whether the client's CertificateVerify signature has been verified.
    ///
    /// Set to `true` only after the client's proof-of-possession signature over
    /// the handshake transcript has been validated against `clientCertificateDER`.
    /// The handshake must not complete with a presented-but-unverified client
    /// certificate.
    public var clientCertificateVerified: Bool = false

    /// Client's ECDHE public key
    public var clientPublicKey: Data?

    /// Our ECDHE key pair
    public var keyExchange: KeyExchange?

    /// Current message sequence number for messages WE send
    public var messageSeq: UInt16 = 0

    /// The next handshake message_seq we expect to RECEIVE from the peer.
    /// Used to discard duplicates (seq < expected) and reject out-of-order future
    /// messages (seq > expected) so the transcript is never corrupted (RFC 6347).
    public var nextReceiveSeq: UInt16 = 0

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
