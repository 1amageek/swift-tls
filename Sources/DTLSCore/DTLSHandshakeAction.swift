/// DTLS Handshake Action (RFC 6347)
///
/// Structured output from handshake processing. Each action instructs
/// DTLSConnection how to handle record-layer transitions and message sending.
///
/// Unlike the flat `DTLSHandshakeResult.outputMessages: [Data]`, actions
/// distinguish plaintext messages, ChangeCipherSpec, and encryption boundaries
/// so the record layer can correctly manage epoch transitions.

import Foundation

/// Output action from DTLS handshake processing
public enum DTLSHandshakeAction: Sendable {
    /// Send a handshake message at the current epoch.
    ///
    /// The data is a complete handshake message (header + body).
    /// DTLSConnection wraps this in a record with the current write epoch.
    case sendMessage(Data)

    /// Send ChangeCipherSpec and advance the write epoch.
    ///
    /// DTLSConnection should:
    /// 1. Encode a CCS record at the current epoch
    /// 2. Install write keys (from a preceding `.keysAvailable`)
    /// 3. Subsequent `.sendMessage` actions use the new epoch
    case sendChangeCipherSpec

    /// Key material is available for installation.
    ///
    /// DTLSConnection stores the key block but does NOT install keys yet.
    /// Write keys are installed on `.sendChangeCipherSpec`.
    /// Read keys are installed when a CCS record is received from the peer.
    case keysAvailable(DTLSKeyBlock, DTLSCipherSuite)

    /// Expect a ChangeCipherSpec from the peer.
    ///
    /// Signals that the next expected record from the peer is CCS,
    /// after which read keys should be installed.
    case expectChangeCipherSpec

    /// The handshake is complete.
    ///
    /// Both sides have verified Finished messages.
    /// Application data can now be sent and received.
    case handshakeComplete
}
