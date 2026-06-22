/// DTLS record layer errors and decode-discard reasons.
///
/// Embedded-clean: pure value types with no Foundation dependency. The
/// `DTLSRecord` codec and the `RecordDecodeResult` (which carries a `DTLSRecord`)
/// remain in the `DTLSRecord` Foundation adapter, but these error / reason enums
/// are pure and shared by both layers.

/// DTLS record layer errors
public enum DTLSRecordError: Error, Sendable {
    case invalidContentType(UInt8)
    case recordOverflow(Int)
    case badRecordMac
    case insufficientData
    case sequenceNumberOverflow
    case invalidEpoch
    case invalidLength(Int)
    case encryptionFailed(String)
    case decryptionFailed(String)
}

extension DTLSRecordError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidContentType(let v):
            return "Invalid content type: \(v)"
        case .recordOverflow(let s):
            return "Record overflow: \(s) bytes"
        case .badRecordMac:
            return "Bad record MAC"
        case .insufficientData:
            return "Insufficient data"
        case .sequenceNumberOverflow:
            return "Sequence number overflow"
        case .invalidEpoch:
            return "Invalid epoch"
        case .invalidLength(let l):
            return "Invalid record length: \(l)"
        case .encryptionFailed(let r):
            return "Encryption failed: \(r)"
        case .decryptionFailed(let r):
            return "Decryption failed: \(r)"
        }
    }
}

/// Reason why a record was discarded
public enum DiscardReason: Sendable, Equatable {
    /// Record is a replay (already received)
    case replayed

    /// Record sequence number is too old (outside replay window)
    case tooOld

    /// Record epoch does not match current read epoch (RFC 6347 §4.1)
    case epochMismatch

    /// AEAD authentication failed (bad MAC / forged record), RFC 6347 §4.1.2.7.
    /// Such records are silently discarded; the datagram loop continues.
    case authenticationFailed

    /// The encrypted fragment is malformed (too short for AEAD overhead, or the
    /// declared plaintext length is out of range). RFC 6347 §4.1.2.7 requires a
    /// silent discard rather than a fatal alert or a crash.
    case malformed
}
