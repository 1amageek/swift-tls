/// `TLSServerEngine` record-layer helpers, send/close, and protector installation.
/// Mirror of `TLSClientEngine+Record`. AEAD via the `CryptoProvider` seam.

import P2PCoreBytes
import P2PCoreCrypto
import TLSWireCore
import TLSCryptoCore
import TLSRecordCore

extension TLSServerEngine {

    // MARK: - send / close

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

    func fragmentPlaintext(type: TLSContentType, content: [UInt8]) -> [UInt8] {
        var result: [UInt8] = []
        let maxSize = TLSRecordCodec.maxPlaintextSize
        if content.isEmpty {
            return TLSRecordCodec.encodePlaintext(type: type, data: [])
        }
        var offset = 0
        while offset < content.count {
            let end = min(offset + maxSize, content.count)
            result.append(contentsOf: TLSRecordCodec.encodePlaintext(type: type, data: Array(content[offset..<end])))
            offset = end
        }
        return result
    }

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
                ciphertext = try protector.protect(content: fragment, type: type, sequenceNumber: sendSequenceNumber)
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
