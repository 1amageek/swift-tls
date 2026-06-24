/// Tier-1 DTLS 1.2 server over UDP datagrams.
///
/// Mirror of `DTLSClient`. The server receives `remoteAddress` for the
/// HelloVerifyRequest cookie binding (RFC 6347 §4.2.1); the facade threads it
/// through `receive(_:from:)`.

import Foundation
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
            return try engine.startHandshake(isClient: false).map { [UInt8]($0) }
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
            let output = try engine.processReceivedDatagram(Data(input), remoteAddress: Data(addr))
            return DTLSOutput(
                datagramsToSend: output.datagramsToSend.map { [UInt8]($0) },
                applicationData: [UInt8](output.applicationData),
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
            return [UInt8](try engine.writeApplicationData(Data(input)))
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Emits a close_notify alert datagram to gracefully terminate.
    public func close() throws(TLSError) -> [UInt8] {
        do {
            return [UInt8](try engine.close())
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Datagrams to retransmit on a timeout (DTLS flight retransmission).
    public func handleTimeout() throws(TLSError) -> [[UInt8]] {
        do {
            return try engine.handleTimeout().map { [UInt8]($0) }
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.isConnected }

    /// Whether the connection has been closed.
    public var isClosed: Bool { engine.isClosed }
}
