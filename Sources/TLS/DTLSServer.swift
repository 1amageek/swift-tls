/// Tier-1 DTLS 1.2 server over UDP datagrams.
///
/// Mirror of `DTLSClient`. The server receives `remoteAddress` for the
/// HelloVerifyRequest cookie binding (RFC 6347 §4.2.1); the facade threads it
/// through `receive(_:from:)`.
///
/// Foundation-free: the facade drives the engine through its `[UInt8]`-currency
/// API; the host-only `Data` bridging lives in the engine, never here.

import DTLSCore
import DTLSRecord

public struct DTLSServer: Sendable {
    private let engine: DTLSConnection

    /// Creates a DTLS server with the given configuration.
    public init(configuration: DTLSConfiguration) throws(TLSError) {
        let certificate = try configuration.makeCertificate()
        self.engine = DTLSConnection(
            certificate: certificate,
            requireClientCertificate: configuration.requireClientCertificate
        )
    }

    /// Starts the handshake. A server has nothing to send until the first
    /// ClientHello arrives; the return is empty.
    public func startHandshake() throws(TLSError) -> [[UInt8]] {
        do {
            return try engine.startHandshakeBytes(isClient: false)
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Feeds a received UDP datagram. `remoteAddress` binds the
    /// HelloVerifyRequest cookie to the client's transport address.
    public func receive(_ datagram: Span<UInt8>, from remoteAddress: Span<UInt8>) throws(TLSError) -> DTLSOutput {
        let input = datagram.facadeArray()
        let addr = remoteAddress.facadeArray()
        do {
            let output = try engine.processReceivedDatagram(input, remoteAddress: addr)
            return DTLSOutput(
                datagramsToSend: output.datagramsToSendBytes,
                applicationData: output.applicationDataBytes,
                handshakeComplete: output.handshakeComplete,
                peerClosed: output.receivedAlert?.alertDescription == .closeNotify,
                anomalies: output.anomalies.map(DTLSOutput.Anomaly.from)
            )
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Encrypts application data and returns the DTLS datagram to send.
    public func send(_ application: Span<UInt8>) throws(TLSError) -> [UInt8] {
        let input = application.facadeArray()
        do {
            return try engine.writeApplicationData(input)
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Emits a close_notify alert datagram to gracefully terminate.
    public func close() throws(TLSError) -> [UInt8] {
        do {
            return try engine.closeBytes()
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Datagrams to retransmit on a timeout (DTLS flight retransmission).
    public func handleTimeout() throws(TLSError) -> [[UInt8]] {
        do {
            return try engine.handleTimeoutBytes()
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.isConnected }

    /// Whether the connection has been closed.
    public var isClosed: Bool { engine.isClosed }

    /// Peer's DER-encoded certificate, if presented. `nil` if the handshake is
    /// incomplete or no certificate was received. X.509 chain validation is the
    /// caller's responsibility; this is the raw leaf the engine recorded.
    /// Currency: `Data` → `[UInt8]` at the facade boundary (consistent with `receive`).
    public var remoteCertificateDER: [UInt8]? {
        engine.remoteCertificateDER.map { [UInt8]($0) }
    }

    /// Peer's SHA-256 certificate fingerprint in RFC 8122 / SDP textual form
    /// (e.g. `"sha-256 AB:CD:..."`), used for WebRTC DTLS-SRTP peer
    /// authentication. `nil` if no peer certificate is available.
    public var remoteFingerprint: String? {
        engine.remoteFingerprint.map { $0.sdpFormat }
    }
}
