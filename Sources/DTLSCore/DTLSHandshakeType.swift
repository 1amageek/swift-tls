/// DTLS Handshake Message Types (RFC 6347 / RFC 5246)
///
/// DTLS 1.2 handshake types. Includes HelloVerifyRequest (type 3) which is DTLS-specific.

import Foundation

/// DTLS 1.2 handshake message type
public enum DTLSHandshakeType: UInt8, Sendable {
    case clientHello = 1
    case serverHello = 2
    case helloVerifyRequest = 3   // DTLS-specific
    case certificate = 11
    case serverKeyExchange = 12
    case certificateRequest = 13
    case serverHelloDone = 14
    case certificateVerify = 15
    case clientKeyExchange = 16
    case finished = 20
}

extension DTLSHandshakeType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .clientHello: return "ClientHello"
        case .serverHello: return "ServerHello"
        case .helloVerifyRequest: return "HelloVerifyRequest"
        case .certificate: return "Certificate"
        case .serverKeyExchange: return "ServerKeyExchange"
        case .certificateRequest: return "CertificateRequest"
        case .serverHelloDone: return "ServerHelloDone"
        case .certificateVerify: return "CertificateVerify"
        case .clientKeyExchange: return "ClientKeyExchange"
        case .finished: return "Finished"
        }
    }
}
