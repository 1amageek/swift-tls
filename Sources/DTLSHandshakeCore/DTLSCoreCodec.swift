/// Wire ↔ FSM codec bridges for the Embedded-clean DTLS handshake FSM.
///
/// The FSM cores throw the closed ``DTLSWireCore/DTLSError`` so the adapter (and
/// the existing test suite) can catch `DTLSError` directly. The wire codec in
/// ``DTLSWireCore`` throws the unified ``DTLSWireCore/DTLSWireError`` (wrapping
/// either a `ByteError` or a `DTLSError`). These helpers run a wire decode and
/// re-throw the *unwrapped* error as `DTLSError`, mapping a low-level `ByteError`
/// onto `DTLSError.invalidFormat` so no error is swallowed and the FSM's typed
/// throw stays closed.
///
/// Encoders trap on a wire-length overflow — an impossible-for-valid-input
/// programmer-contract violation — matching the legacy `Data`-writer behaviour
/// (a loud, non-silent crash; there is no valid fallback for an unencodable
/// message).
///
/// Embedded-clean: no Foundation, no `any`, typed throws.

import P2PCoreBytes
import DTLSWireCore

extension DTLSHandshakeHeader {
    /// Encodes a complete handshake message (header + body), trapping on overflow.
    static func encodeMessageOrTrap(
        type: DTLSHandshakeType,
        messageSeq: UInt16,
        body: [UInt8]
    ) -> [UInt8] {
        do {
            return try encodeMessage(type: type, messageSeq: messageSeq, body: body)
        } catch {
            fatalError("DTLS handshake message encoding exceeded a wire length bound")
        }
    }
}

// MARK: - Encode helpers (trap on wire-length overflow)

func encodeBytesOrTrap(_ message: DTLSServerHello) -> [UInt8] {
    do { return try message.encodeBytes() }
    catch { fatalError("DTLS ServerHello encoding exceeded a wire length bound") }
}

func encodeBytesOrTrap(_ message: ServerHelloDone) -> [UInt8] {
    do { return try message.encodeBytes() }
    catch { fatalError("DTLS ServerHelloDone encoding exceeded a wire length bound") }
}

func encodeBytesOrTrap(_ message: ClientKeyExchange) -> [UInt8] {
    do { return try message.encodeBytes() }
    catch { fatalError("DTLS ClientKeyExchange encoding exceeded a wire length bound") }
}

func encodeBytesOrTrap(_ message: DTLSFinished) -> [UInt8] {
    do { return try message.encodeBytes() }
    catch { fatalError("DTLS Finished encoding exceeded a wire length bound") }
}

/// Maps a wire-codec ``DTLSWireError`` onto the closed ``DTLSError`` the FSM throws.
@inline(__always)
func mapWireError(_ error: DTLSWireError) -> DTLSError {
    switch error {
    case .dtls(let e):
        return e
    case .bytes(let e):
        return .invalidFormat("Wire decode failed: \(e)")
    }
}

// MARK: - Decode wrappers (DTLSWireError → DTLSError)

func decodeServerHello(_ body: [UInt8]) throws(DTLSError) -> DTLSServerHello {
    do { return try DTLSServerHello.decode(from: body) }
    catch { throw mapWireError(error) }
}

func decodeCertificate(_ body: [UInt8]) throws(DTLSError) -> CertificateMessage {
    do { return try CertificateMessage.decode(from: body) }
    catch { throw mapWireError(error) }
}

func decodeServerKeyExchange(_ body: [UInt8]) throws(DTLSError) -> ServerKeyExchange {
    do { return try ServerKeyExchange.decode(from: body) }
    catch { throw mapWireError(error) }
}

func decodeServerHelloDone(_ body: [UInt8]) throws(DTLSError) -> ServerHelloDone {
    do { return try ServerHelloDone.decode(from: body) }
    catch { throw mapWireError(error) }
}

func decodeClientKeyExchange(_ body: [UInt8]) throws(DTLSError) -> ClientKeyExchange {
    do { return try ClientKeyExchange.decode(from: body) }
    catch { throw mapWireError(error) }
}

func decodeClientHello(_ body: [UInt8]) throws(DTLSError) -> DTLSClientHello {
    do { return try DTLSClientHello.decode(from: body) }
    catch { throw mapWireError(error) }
}

func decodeFinished(_ body: [UInt8]) throws(DTLSError) -> DTLSFinished {
    do { return try DTLSFinished.decode(from: body) }
    catch { throw mapWireError(error) }
}

/// Decodes a HelloVerifyRequest body inline (version + opaque cookie<0..255>),
/// returning the cookie bytes. The HVR wire framing lives in the adapter
/// (`HelloVerifyRequest`); the FSM only needs the cookie.
func decodeHelloVerifyRequestCookie(_ body: [UInt8]) throws(DTLSError) -> [UInt8] {
    var reader = ByteReader(body)
    do {
        // ProtocolVersion server_version (2 bytes), then opaque cookie<0..2^8-1>.
        _ = try reader.readUInt16()
        return try reader.readVector8()
    } catch {
        throw DTLSError.invalidFormat("HelloVerifyRequest decode failed: \(error)")
    }
}
