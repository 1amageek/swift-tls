/// DTLS Session
///
/// Represents an established DTLS session after handshake completion.
/// Provides application-level encrypt/decrypt API.

import Foundation
import Crypto
import DTLSCore

/// An established DTLS session for encrypting/decrypting application data
public struct DTLSSession: Sendable {
    /// Our certificate
    public let localCertificate: DTLSCertificate

    /// Remote peer's DER-encoded certificate
    public let remoteCertificateDER: Data

    /// Remote peer's certificate fingerprint
    public let remoteFingerprint: CertificateFingerprint

    /// Negotiated cipher suite
    public let cipherSuite: DTLSCipherSuite

    /// Encryption key for outgoing data
    private let writeKey: SymmetricKey
    private let writeFixedIV: Data

    /// Decryption key for incoming data
    private let readKey: SymmetricKey
    private let readFixedIV: Data

    /// Write epoch
    private let epoch: UInt16

    /// Current write sequence number
    private var writeSequenceNumber: UInt64 = 0

    public init(
        localCertificate: DTLSCertificate,
        remoteCertificateDER: Data,
        cipherSuite: DTLSCipherSuite,
        keyBlock: DTLSKeyBlock,
        isClient: Bool,
        epoch: UInt16 = 1
    ) {
        self.localCertificate = localCertificate
        self.remoteCertificateDER = remoteCertificateDER
        self.remoteFingerprint = CertificateFingerprint.fromDER(remoteCertificateDER)
        self.cipherSuite = cipherSuite
        self.epoch = epoch

        if isClient {
            self.writeKey = SymmetricKey(data: keyBlock.clientWriteKey)
            self.writeFixedIV = keyBlock.clientWriteIV
            self.readKey = SymmetricKey(data: keyBlock.serverWriteKey)
            self.readFixedIV = keyBlock.serverWriteIV
        } else {
            self.writeKey = SymmetricKey(data: keyBlock.serverWriteKey)
            self.writeFixedIV = keyBlock.serverWriteIV
            self.readKey = SymmetricKey(data: keyBlock.clientWriteKey)
            self.readFixedIV = keyBlock.clientWriteIV
        }
    }

    /// Encrypt application data into a DTLS record
    /// - Parameter plaintext: The application data to encrypt
    /// - Returns: Complete DTLS record bytes
    public mutating func encrypt(_ plaintext: Data) throws -> Data {
        let seqNum = writeSequenceNumber
        writeSequenceNumber += 1

        let explicitNonce = buildExplicitNonce(epoch: epoch, sequenceNumber: seqNum)

        var record = DTLSRecord(
            contentType: .applicationData,
            epoch: epoch,
            sequenceNumber: seqNum,
            fragment: plaintext
        )

        let aad = record.buildAAD(plaintextLength: plaintext.count)
        let encrypted = try DTLSRecordCryptor.seal(
            plaintext: plaintext,
            key: writeKey,
            fixedIV: writeFixedIV,
            explicitNonce: explicitNonce,
            additionalData: aad
        )

        record.fragment = encrypted
        return record.encode()
    }

    /// Decrypt a received DTLS record
    /// - Parameter recordData: Complete DTLS record bytes
    /// - Returns: Decrypted application data
    public func decrypt(_ recordData: Data) throws -> Data {
        guard let (record, _) = try DTLSRecord.decode(from: recordData) else {
            throw DTLSRecordError.insufficientData
        }

        guard record.contentType == .applicationData else {
            throw DTLSRecordError.invalidContentType(record.contentType.rawValue)
        }

        let plaintextLen = record.fragment.count - 8 - 16 // subtract explicit nonce + tag
        let aad = record.buildAAD(plaintextLength: plaintextLen)

        return try DTLSRecordCryptor.open(
            ciphertext: record.fragment,
            key: readKey,
            fixedIV: readFixedIV,
            additionalData: aad
        )
    }

    // MARK: - Private

    private func buildExplicitNonce(epoch: UInt16, sequenceNumber: UInt64) -> Data {
        var writer = TLSWriter()
        writer.writeUInt16(epoch)
        writer.writeUInt16(UInt16((sequenceNumber >> 32) & 0xFFFF))
        writer.writeUInt32(UInt32(sequenceNumber & 0xFFFFFFFF))
        return writer.finish()
    }
}
