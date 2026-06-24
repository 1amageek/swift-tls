/// Tier-1 TLS 1.3 client over a reliable byte stream (TCP).
///
/// The non-generic facade fixed to `DefaultCryptoProvider`. It wraps the package
/// record engine (`TLSConnection`, specialised at the unified `TLSProvider`) and
/// presents a `[UInt8]`/`Span<UInt8>` surface with a single `TLSError`.
///
/// The methods are `async` because the underlying handshake engine is `async`;
/// they never actually suspend (the engine is lock-based, not I/O-bound), so they
/// complete promptly. Typed throws keeps the error surface to one enum.
///
/// Usage:
/// 1. `startHandshake()` → send the returned bytes to the peer.
/// 2. Feed peer bytes into `receive(_:)`; send `output.bytesToSend`; read
///    `output.applicationData`; check `output.handshakeComplete`.
/// 3. After the handshake, `send(_:)` encrypts application data.
/// 4. `close()` emits a close_notify.

import TLSCore
import TLSRecord

public struct TLSClient: Sendable {
    private let engine: TLSConnection

    /// Creates a TLS client with the given configuration.
    public init(configuration: TLSConfiguration = .init()) throws(TLSError) {
        let engineConfig = try configuration.makeEngineConfiguration()
        self.engine = TLSConnection(configuration: engineConfig)
    }

    /// Starts the handshake, returning the ClientHello bytes to send.
    public func startHandshake() async throws(TLSError) -> [UInt8] {
        do {
            let data = try await engine.startHandshake(isClient: true)
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
