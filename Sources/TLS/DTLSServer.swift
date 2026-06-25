/// Tier-1 DTLS 1.2 server over UDP datagrams.
///
/// Mirror of `DTLSClient`, wrapping the cored, Embedded-clean
/// `DTLSServerEngine<TLSCryptoProvider>` (in `DTLSEngineCore`) under a `Mutex`. The
/// server receives `remoteAddress` for the HelloVerifyRequest cookie binding
/// (RFC 6347 §4.2.1); the facade threads it through `receive(_:from:)`.
///
/// ECDHE, the ServerKeyExchange signing, the client CertificateVerify
/// verification, and the HelloVerifyRequest cookie HMAC are INJECTED into the
/// engine via the host strategy bridge
/// (`DTLSCertificate.makeDTLSEngineConfiguration`, gated `#if canImport(Foundation)`);
/// X.509 never enters the engine itself.

import Foundation
import Synchronization
import TLSCore
import DTLSCore
import DTLSEngineCore

public final class DTLSServer: Sendable {
    private let engine: Mutex<DTLSServerEngine<TLSCryptoProvider>>

    /// Creates a DTLS server with the given configuration.
    public init(configuration: DTLSConfiguration) throws(TLSError) {
        let certificate = try configuration.makeCertificate()
        let engineConfig = certificate.makeDTLSEngineConfiguration(
            requireClientCertificate: configuration.requireClientCertificate
        )
        let created: DTLSServerEngine<TLSCryptoProvider>
        do {
            created = try DTLSServerEngine<TLSCryptoProvider>(configuration: engineConfig)
        } catch {
            throw TLSError.fromDTLSEngine(error)
        }
        self.engine = Mutex(created)
    }

    /// Starts the handshake. A server has nothing to send until the first
    /// ClientHello arrives; the return is empty.
    public func startHandshake() throws(TLSError) -> [[UInt8]] {
        try run { try $0.startHandshake() }
    }

    /// Feeds a received UDP datagram. `remoteAddress` binds the
    /// HelloVerifyRequest cookie to the client's transport address.
    public func receive(_ datagram: Span<UInt8>, from remoteAddress: Span<UInt8>) throws(TLSError) -> DTLSOutput {
        let input = datagram.facadeArray()
        let addr = remoteAddress.facadeArray()
        let output = try run { try $0.receive(input.span, from: addr.span) }
        return DTLSOutput(from: output)
    }

    /// Encrypts application data and returns the DTLS datagram to send.
    public func send(_ application: Span<UInt8>) throws(TLSError) -> [UInt8] {
        let input = application.facadeArray()
        return try run { try $0.send(input.span) }
    }

    /// Emits a close_notify alert datagram to gracefully terminate.
    public func close() throws(TLSError) -> [UInt8] {
        try run { try $0.close() }
    }

    /// Datagrams to retransmit on a timeout (DTLS flight retransmission).
    public func handleTimeout() throws(TLSError) -> [[UInt8]] {
        try run { try $0.handleTimeout() }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.withLock { $0.isEstablished } }

    /// Whether the connection has been closed.
    public var isClosed: Bool { engine.withLock { $0.isClosed } }

    /// Peer's DER-encoded certificate, if presented. `nil` if the handshake is
    /// incomplete or no certificate was received. X.509 chain validation is the
    /// caller's responsibility; this is the raw leaf the engine recorded.
    public var remoteCertificateDER: [UInt8]? {
        engine.withLock { $0.remoteCertificateDER }
    }

    /// Peer's SHA-256 certificate fingerprint in RFC 8122 / SDP textual form
    /// (e.g. `"sha-256 AB:CD:..."`), used for WebRTC DTLS-SRTP peer
    /// authentication. `nil` if no peer certificate is available.
    public var remoteFingerprint: String? {
        guard let der = remoteCertificateDER else { return nil }
        return CertificateFingerprint.fromDER(Data(der)).sdpFormat
    }

    /// Runs an engine operation under the lock, mapping any engine error to the
    /// single facade `TLSError`. The facade is the caller that locks.
    private func run<R: Sendable>(
        _ body: (inout DTLSServerEngine<TLSCryptoProvider>) throws -> R
    ) throws(TLSError) -> R {
        let result: Result<R, TLSError> = engine.withLock { engine in
            do {
                return .success(try body(&engine))
            } catch let error as DTLSEngineError {
                return .failure(TLSError.fromDTLSEngine(error))
            } catch {
                return .failure(.internalError(reason: String(describing: error)))
            }
        }
        switch result {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}
