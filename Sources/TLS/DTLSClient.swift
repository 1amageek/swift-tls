/// Tier-1 DTLS 1.2 client over UDP datagrams.
///
/// Non-generic facade fixed to `TLSProvider`. Wraps the package `DTLSConnection`
/// engine and presents a `[UInt8]`/`Span<UInt8>` surface with one `TLSError`. The
/// datagram methods return `[[UInt8]]` (a list of datagrams to send), matching
/// DTLS's record-per-datagram model.

import Foundation
import DTLSCore
import DTLSRecord

public struct DTLSClient: Sendable {
    private let engine: DTLSConnection

    /// Creates a DTLS client with the given configuration.
    public init(configuration: DTLSConfiguration) throws(TLSError) {
        let certificate = try configuration.makeCertificate()
        self.engine = DTLSConnection(
            certificate: certificate,
            requireClientCertificate: configuration.requireClientCertificate
        )
    }

    /// Starts the handshake, returning the ClientHello datagram(s) to send.
    public func startHandshake() throws(TLSError) -> [[UInt8]] {
        do {
            return try engine.startHandshake(isClient: true).map { [UInt8]($0) }
        } catch {
            throw TLSError.fromDTLS(error)
        }
    }

    /// Feeds a received UDP datagram and returns the aggregate effects.
    public func receive(_ datagram: Span<UInt8>) throws(TLSError) -> DTLSOutput {
        let input = datagram.facadeArray()
        do {
            let output = try engine.processReceivedDatagram(Data(input))
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
