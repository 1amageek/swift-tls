/// DTLS 1.2 Client State Machine
///
/// Tracks the client's progress through the DTLS handshake:
///   idle → waitingServerHello → waitingCertificate → waitingServerKeyExchange
///   → waitingServerHelloDone → waitingChangeCipherSpec → waitingFinished → connected

import Foundation
import TLSCore
import TLSWireCore
import DTLSWireCore
import DTLSHandshakeCore

/// Client handshake state
public enum DTLSClientState: Sendable, Equatable {
    /// Initial state, no handshake started
    case idle

    /// ClientHello sent, waiting for HelloVerifyRequest or ServerHello
    case waitingServerHello

    /// Received HelloVerifyRequest, resending ClientHello with cookie
    case waitingServerHelloWithCookie

    /// Waiting for server Certificate
    case waitingCertificate

    /// Waiting for ServerKeyExchange
    case waitingServerKeyExchange

    /// Waiting for ServerHelloDone
    case waitingServerHelloDone

    /// Sent client flight (Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished)
    /// Waiting for server CCS
    case waitingChangeCipherSpec

    /// Waiting for server Finished
    case waitingFinished

    /// Handshake complete
    case connected

    /// Error state
    case failed(String)

    /// Bridge from the Embedded-clean FSM state.
    init(core: DTLSClientHandshake<TLSCryptoProvider>.ClientState) {
        switch core {
        case .idle: self = .idle
        case .waitingServerHello: self = .waitingServerHello
        case .waitingServerHelloWithCookie: self = .waitingServerHelloWithCookie
        case .waitingCertificate: self = .waitingCertificate
        case .waitingServerKeyExchange: self = .waitingServerKeyExchange
        case .waitingServerHelloDone: self = .waitingServerHelloDone
        case .waitingChangeCipherSpec: self = .waitingChangeCipherSpec
        case .waitingFinished: self = .waitingFinished
        case .connected: self = .connected
        }
    }
}

/// Client handshake context — mutable state accumulated during handshake
public struct DTLSClientContext: Sendable {
    /// Our client random
    public var clientRandom: Data?

    /// Server random
    public var serverRandom: Data?

    /// Negotiated cipher suite
    public var cipherSuite: DTLSCipherSuite?

    /// Server's certificate (DER)
    public var serverCertificateDER: Data?

    /// Server's ECDHE public key
    public var serverPublicKey: Data?

    /// Server's named group
    public var serverNamedGroup: TLSWireCore.NamedGroup?

    /// Our ECDHE key pair
    public var keyExchange: KeyExchange?

    /// Cookie from HelloVerifyRequest
    public var cookie: Data?

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
