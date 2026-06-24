/// Tier-1 TLS 1.3 server over a reliable byte stream (TCP).
///
/// Mirror of `TLSClient`, fixed to `DefaultCryptoProvider`. A server requires
/// identity material (signing key + certificate chain) in its configuration.

import TLSCore
import TLSRecord

public struct TLSServer: Sendable {
    private let engine: TLSConnection

    /// Creates a TLS server. The configuration must carry identity material.
    public init(configuration: TLSConfiguration) throws(TLSError) {
        let engineConfig = try configuration.makeEngineConfiguration()
        self.engine = TLSConnection(configuration: engineConfig)
    }

    /// Starts the handshake. For a server this returns no bytes until the client's
    /// ClientHello arrives; the return is empty.
    public func startHandshake() async throws(TLSError) -> [UInt8] {
        do {
            let data = try await engine.startHandshake(isClient: false)
            return [UInt8](data)
        } catch {
            throw TLSError.from(error)
        }
    }

    /// Feeds bytes received from the peer and returns the aggregate effects.
    public func receive(_ bytes: Span<UInt8>) async throws(TLSError) -> TLSOutput {
        let input = bytes.facadeArray()
        do {
            let output = try await engine.processReceivedData(input)
            return TLSOutput(
                bytesToSend: [UInt8](output.dataToSend),
                applicationData: [UInt8](output.applicationData),
                handshakeComplete: output.handshakeComplete,
                peerClosed: output.alert?.alertDescription == .closeNotify
            )
        } catch {
            throw TLSError.from(error)
        }
    }

    /// Encrypts application data and returns the TLS records to send.
    public func send(_ application: Span<UInt8>) async throws(TLSError) -> [UInt8] {
        let input = application.facadeArray()
        do {
            return [UInt8](try engine.writeApplicationData(input))
        } catch {
            throw TLSError.from(error)
        }
    }

    /// Emits a close_notify alert (encoded record) to gracefully terminate.
    public func close() async throws(TLSError) -> [UInt8] {
        do {
            return [UInt8](try engine.close())
        } catch {
            throw TLSError.from(error)
        }
    }

    /// Whether the handshake is complete and the connection is usable.
    public var isEstablished: Bool { engine.isConnected }

    /// The negotiated ALPN protocol, if any.
    public var negotiatedALPN: String? { engine.negotiatedALPN }

    /// The application peer identity returned by the certificate validator, if any.
    public var peerIdentity: PeerIdentity? {
        engine.validatedPeerInfo as? PeerIdentity
    }
}
