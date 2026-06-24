/// `TLSClientEngine` record-layer helpers, send/close, and private-state bridges.
///
/// The record layer is owned by the engine (caller-locked): one
/// ``TLSRecordSuiteProtector`` per direction plus its sequence counter. Secrets
/// flow in from the cored FSM as raw `[UInt8]`; the engine derives the AEAD key +
/// IV and builds the protector. All AEAD goes through the `CryptoProvider` seam —
/// no swift-crypto, no Foundation.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSRecordCore

extension TLSClientEngine {

    // MARK: - send / close (public API)

    /// Encrypts application data into TLS records to send. Throws if the handshake
    /// is not complete or the connection is closed.
    public mutating func send(_ application: Span<UInt8>) throws(TLSEngineError) -> [UInt8] {
        guard isEstablished else {
            if isClosed { throw .connectionClosed }
            throw .handshakeNotComplete
        }
        guard sendProtector != nil else {
            throw .internalError(reason: "no send protector after handshake")
        }
        return try encryptAndFrame(content: application.facadeArrayLocal(), type: .applicationData)
    }

    /// Emits a close_notify alert record (encrypted if keys are active).
    public mutating func close() throws(TLSEngineError) -> [UInt8] {
        guard !isClosed else { return [] }
        markClosed()
        let alertBytes = TLSAlert.closeNotify.encodeBytes()
        if sendProtector != nil {
            return try encryptAndFrame(content: alertBytes, type: .alert)
        }
        return TLSRecordCodec.encodePlaintext(type: .alert, data: alertBytes)
    }

    // MARK: - Record framing

    /// Fragments plaintext into one or more TLS records (RFC 8446 §5.1).
    func fragmentPlaintext(type: TLSContentType, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = []
        let maxSize = TLSRecordCodec.maxPlaintextSize
        var offset = 0
        if content.isEmpty {
            return TLSRecordCodec.encodePlaintext(type: type, data: [])
        }
        while offset < content.count {
            let end = min(offset + maxSize, content.count)
            let fragment = Array(content[offset..<end])
            result.append(contentsOf: TLSRecordCodec.encodePlaintext(type: type, data: fragment))
            offset = end
        }
        return result
    }

    /// Encrypts content with the active send protector, fragmenting as needed,
    /// advancing the send sequence number per record.
    mutating func encryptAndFrame(
        content: [UInt8],
        type: TLSContentType
    ) throws(TLSEngineError) -> [UInt8] {
        guard let protector = sendProtector else {
            throw .internalError(reason: "encrypt without send protector")
        }
        var result: [UInt8] = []
        let maxSize = TLSRecordCodec.maxPlaintextSize
        var offset = 0
        repeat {
            let end = min(offset + maxSize, content.count)
            let fragment = Array(content[offset..<end])
            let ciphertext: [UInt8]
            do {
                ciphertext = try protector.protect(
                    content: fragment,
                    type: type,
                    sequenceNumber: sendSequenceNumber
                )
            } catch {
                throw .protocolFailure(reason: "record encryption failed: \(error)")
            }
            sendSequenceNumber &+= 1
            result.append(contentsOf: TLSRecordCodec.encodeCiphertext(ciphertext))
            offset = end
        } while offset < content.count
        return result
    }

    // MARK: - Protector installation

    /// Installs the send/receive protectors for `cipherSuite` from raw secrets.
    /// A `nil` secret leaves that direction's protector untouched (e.g. a key
    /// update that rotates one direction only). Each direction's sequence number
    /// resets when its protector is (re)installed.
    mutating func installProtectors(
        cipherSuite: CipherSuite,
        sendSecret: [UInt8]?,
        receiveSecret: [UInt8]?
    ) throws(TLSEngineError) {
        recordCipherSuite = cipherSuite
        if let sendSecret {
            let protector: TLSRecordSuiteProtector<C>
            do {
                protector = try TLSRecordSuiteProtector<C>.fromSecret(cipherSuite: cipherSuite, secret: sendSecret)
            } catch {
                throw .internalError(reason: "send protector derivation failed: \(error)")
            }
            sendProtector = protector
            sendSequenceNumber = 0
        }
        if let receiveSecret {
            let protector: TLSRecordSuiteProtector<C>
            do {
                protector = try TLSRecordSuiteProtector<C>.fromSecret(cipherSuite: cipherSuite, secret: receiveSecret)
            } catch {
                throw .internalError(reason: "receive protector derivation failed: \(error)")
            }
            receiveProtector = protector
            receiveSequenceNumber = 0
        }
    }
}

// MARK: - Local Span → [UInt8] bulk copy (no Foundation)

extension Span where Element == UInt8 {
    /// Bulk `Span<UInt8>` → `[UInt8]` (one `update(from:)`), Embedded-clean.
    @inline(__always)
    func facadeArrayLocal() -> [UInt8] {
        let n = count
        guard n > 0 else { return [] }
        return [UInt8](unsafeUninitializedCapacity: n) { destination, initializedCount in
            withUnsafeBufferPointer { source in
                destination.baseAddress!.update(from: source.baseAddress!, count: n)
            }
            initializedCount = n
        }
    }
}
