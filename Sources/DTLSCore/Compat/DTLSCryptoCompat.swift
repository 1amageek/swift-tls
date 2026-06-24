/// Crypto- and X.509-bound convenience members for the moved DTLS wire message
/// types.
///
/// The Embedded-clean `DTLSWireCore` holds only the pure wire codec. The members
/// that sign / verify (swift-crypto), generate cookies (the rotating cookie secret
/// provider), or wrap a self-signed certificate (swift-certificates) cannot live in
/// an Embedded target, so they are restored here in the Foundation adapter, where
/// `KeyExchange` / `SigningKey` / `VerificationKey` / `DTLSCertificate` /
/// `DTLSCookieSecretProvider` are available.

import Foundation
import TLSCore
import DTLSWireCore

// MARK: - ServerKeyExchange: sign / verify

extension ServerKeyExchange {
    /// Create and sign a ServerKeyExchange.
    /// - Parameters:
    ///   - keyExchange: The ECDHE key pair
    ///   - signingKey: The server's signing key
    ///   - clientRandom: 32-byte client random
    ///   - serverRandom: 32-byte server random
    /// - Returns: Signed ServerKeyExchange
    public static func create(
        keyExchange: KeyExchange,
        signingKey: SigningKey,
        clientRandom: Data,
        serverRandom: Data
    ) throws -> ServerKeyExchange {
        let publicKeyBytes = keyExchange.publicKeyBytes
        let namedGroup = keyExchange.group

        // Build the data to sign:
        // client_random + server_random + curve_params + public_key
        let paramsData: [UInt8]
        do {
            paramsData = try encodeParams(namedGroup: namedGroup, publicKey: [UInt8](publicKeyBytes))
        } catch {
            try error.rethrowUnwrapped()
        }
        let signedData = clientRandom + serverRandom + Data(paramsData)
        let signature = try signingKey.sign(signedData)

        return ServerKeyExchange(
            namedGroup: namedGroup,
            publicKey: publicKeyBytes,
            signatureScheme: signingKey.scheme,
            signature: signature
        )
    }

    /// Verify the signature.
    public func verify(
        clientRandom: Data,
        serverRandom: Data,
        verificationKey: VerificationKey
    ) throws -> Bool {
        let paramsData: [UInt8]
        do {
            paramsData = try Self.encodeParams(namedGroup: namedGroup, publicKey: publicKey)
        } catch {
            try error.rethrowUnwrapped()
        }
        let signedData = clientRandom + serverRandom + Data(paramsData)
        return try verificationKey.verify(signature: Data(signature), for: signedData)
    }
}

// MARK: - CertificateVerify: sign / verify

extension CertificateVerify {
    /// Create a CertificateVerify by signing the handshake hash.
    /// - Parameters:
    ///   - handshakeHash: Hash of all handshake messages so far
    ///   - signingKey: The client's signing key
    /// - Returns: Signed CertificateVerify
    public static func create(
        handshakeHash: Data,
        signingKey: SigningKey
    ) throws -> CertificateVerify {
        let signature = try signingKey.sign(handshakeHash)
        return CertificateVerify(
            signatureScheme: signingKey.scheme,
            signature: signature
        )
    }

    /// Verify the signature against the handshake hash.
    public func verify(
        handshakeHash: Data,
        verificationKey: VerificationKey
    ) throws -> Bool {
        try verificationKey.verify(signature: Data(signature), for: handshakeHash)
    }
}

// MARK: - CertificateMessage: from DTLSCertificate

extension CertificateMessage {
    /// Create from a single DTLSCertificate.
    public init(certificate: DTLSCertificate) {
        self.init(certificates: [certificate.derEncoded])
    }
}

// MARK: - HandshakeReassemblyBuffer: Data wrappers

extension HandshakeReassemblyBuffer {
    /// Add a fragment — `Data` body in, complete reassembled message `Data?` out.
    @discardableResult
    public mutating func addFragment(header: DTLSHandshakeHeader, body: Data) throws -> Data? {
        let result: [UInt8]?
        do {
            result = try addFragment(header: header, body: [UInt8](body))
        } catch {
            try error.rethrowUnwrapped()
        }
        return result.map { Data($0) }
    }

    /// Split a DTLS handshake record payload into its fragments — `Data` in/out.
    public static func parseMessages(
        from recordFragment: Data
    ) throws -> [(header: DTLSHandshakeHeader, body: Data)] {
        let parsed: [(header: DTLSHandshakeHeader, body: [UInt8])]
        do {
            parsed = try parseMessages(from: [UInt8](recordFragment))
        } catch {
            try error.rethrowUnwrapped()
        }
        return parsed.map { (header: $0.header, body: Data($0.body)) }
    }
}
