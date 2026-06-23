/// Output actions emitted by the Embedded-clean DTLS 1.2 handshake FSM.
///
/// The sans-IO FSM core performs no I/O: each transition returns the side effects
/// the adapter must carry out — handshake message bytes to send, the derived key
/// block + negotiated cipher suite, epoch-transition signals, and completion — as a
/// flat list of these value-type actions. The `DTLSCore` adapter translates them
/// into the Foundation `DTLSHandshakeAction` stream (bridging `[UInt8]` ↔ `Data`,
/// `DTLSKeyBlockCore` ↔ `DTLSKeyBlock`).
///
/// Ordering is significant and preserved verbatim: the adapter emits actions in the
/// order the core returns them so the wire flight and key-availability sequence stay
/// byte-identical to the pre-FSM implementation.
///
/// Embedded-clean: no Foundation, no `any`, no Mutex, value types only.

import DTLSWireCore

/// A single side effect the adapter must carry out.
public enum DTLSCoreAction: Sendable, Equatable {
    /// Send these complete handshake message bytes (12-byte header + body) at the
    /// current write epoch.
    case sendMessage([UInt8])

    /// Send ChangeCipherSpec and advance the write epoch (install write keys from a
    /// preceding `.keysAvailable`).
    case sendChangeCipherSpec

    /// Key material is available; the adapter stores the key block but installs keys
    /// on the CCS boundaries.
    case keysAvailable(DTLSKeyBlockCore, DTLSCipherSuite)

    /// Expect a ChangeCipherSpec from the peer (install read keys on receipt).
    case expectChangeCipherSpec

    /// The handshake is complete; both Finished messages verified.
    case handshakeComplete
}
