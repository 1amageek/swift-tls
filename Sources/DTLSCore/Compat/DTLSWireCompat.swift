/// Foundation `Data` compatibility layer over the Embedded-clean `DTLSWireCore`.
///
/// `DTLSWireCore` expresses the DTLS wire codec over `[UInt8]`/`P2PCoreBytes` so it
/// can build under Embedded Swift. This adapter file restores the historical
/// `Data`-based public surface that the rest of `swift-tls` (the DTLS handshake
/// handler, record layer, X.509 glue) and the existing test suite bind to. It is
/// pure bridging: `Data <-> [UInt8]` conversions plus typed-throws unwrapping. No
/// new protocol or wire logic lives here.

import Foundation
import P2PCoreBytes
@_exported import TLSCore
@_exported import DTLSWireCore

// MARK: - Disambiguation

/// `DTLSWireCore.CertificateVerify` (DTLS 1.2) and `TLSWireCore.CertificateVerify`
/// (TLS 1.3) share a name. Before the wire-codec extraction the DTLS type was
/// defined *in* this module, so it shadowed the TLS one for `DTLSCore` callers and
/// for `@testable import DTLSCore` tests. This module-local typealias restores that
/// precedence: `CertificateVerify` unqualified resolves to the DTLS message.
public typealias CertificateVerify = DTLSWireCore.CertificateVerify

// MARK: - DTLSWireError unwrapping

extension DTLSWireError {
    /// Rethrows the *wrapped* concrete error (`ByteError` / `DTLSError`).
    ///
    /// The Embedded-clean core uses a single typed-throws error (`DTLSWireError`);
    /// this restores the historical behaviour where callers (and the test suite)
    /// catch `DTLSError` / `ByteError` directly.
    ///
    /// Usage at a `Data`-API boundary that calls a typed-throws core method:
    /// ```swift
    /// do { return try coreCall() } catch { try error.rethrowUnwrapped() }
    /// ```
    /// In the bare `catch`, `error` has static type `DTLSWireError` (the core's
    /// typed throw), so this avoids the generic-helper / `catch as` forms that
    /// currently miscompile with typed throws.
    public func rethrowUnwrapped() throws -> Never {
        switch self {
        case .bytes(let e): throw e
        case .dtls(let e): throw e
        }
    }
}

// MARK: - Encode helper

/// Runs a throwing byte encoder and returns `Data`, trapping on the
/// impossible-for-valid-input wire-length overflow (matching the historical
/// trapping behaviour of the `Data`-based writer).
@inline(__always)
func encodeDTLSData(_ body: () throws -> [UInt8]) -> Data {
    do {
        return Data(try body())
    } catch {
        fatalError("DTLS message encoding exceeded a wire length bound: \(error)")
    }
}
