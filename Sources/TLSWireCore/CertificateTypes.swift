/// TLS Certificate Type Extensions (RFC 7250)
///
/// The client_certificate_type (19) and server_certificate_type (20)
/// extensions negotiate the format of the Certificate message payload:
/// X.509 certificates or Raw Public Keys (SubjectPublicKeyInfo).
///
/// Context varies by message type:
/// - ClientHello: list of supported types in preference order
/// - EncryptedExtensions: the single selected type
///
/// ```
/// struct {
///     select(ClientOrServerExtension) {
///         case client:
///           CertificateType client_certificate_types<1..2^8-1>;
///         case server:
///           CertificateType client_certificate_type;
///     }
/// } ClientCertTypeExtension;
///
/// struct {
///     select(ClientOrServerExtension) {
///         case client:
///           CertificateType server_certificate_types<1..2^8-1>;
///         case server:
///           CertificateType server_certificate_type;
///     }
/// } ServerCertTypeExtension;
/// ```

import P2PCoreBytes

// MARK: - Certificate Type

/// Certificate types (RFC 7250 Section 3, IANA TLS Certificate Types registry)
public enum CertificateType: UInt8, Sendable, Equatable {
    /// X.509 certificate chain (RFC 8446 default)
    case x509 = 0

    /// Raw Public Key: DER-encoded SubjectPublicKeyInfo (RFC 7250)
    case rawPublicKey = 2
}

// MARK: - Shared Codec

/// Wire codec shared by the client/server certificate type extensions.
enum CertificateTypeCodec {

    /// Encode the ClientHello form: a 1-byte length-prefixed list.
    static func encodeOffered(_ types: [CertificateType]) throws(TLSWireError) -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: 1 + types.count)
        try writer.wWriteVector8(types.map { $0.rawValue })
        return writer.finishArray()
    }

    /// Encode the EncryptedExtensions form: a single byte.
    static func encodeSelected(_ type: CertificateType) -> [UInt8] {
        [type.rawValue]
    }

    /// Decode the ClientHello form.
    ///
    /// Unknown certificate type values are ignored (the peer may offer
    /// types we do not implement), but the list itself must be non-empty.
    static func decodeOffered(from data: [UInt8], extensionName: String) throws(TLSWireError) -> [CertificateType] {
        var reader = ByteReader(data)
        let listData = try reader.wReadVector8()
        guard reader.remaining == 0 else {
            throw TLSWireError.decode(.invalidFormat("\(extensionName): trailing bytes after type list"))
        }
        guard !listData.isEmpty else {
            throw TLSWireError.decode(.invalidFormat("\(extensionName): empty certificate type list"))
        }

        var types: [CertificateType] = []
        for byte in listData {
            if let type = CertificateType(rawValue: byte) {
                types.append(type)
            }
            // Unknown certificate types are ignored
        }
        return types
    }

    /// Decode the EncryptedExtensions form.
    ///
    /// The selected type must be one we know: the server may only select
    /// a type the client offered, and we only offer known types.
    static func decodeSelected(from data: [UInt8], extensionName: String) throws(TLSWireError) -> CertificateType {
        guard data.count == 1 else {
            throw TLSWireError.decode(.invalidFormat("\(extensionName): expected single selected type byte"))
        }
        guard let type = CertificateType(rawValue: data[0]) else {
            throw TLSWireError.decode(.invalidFormat(
                "\(extensionName): unknown selected certificate type \(data[0])"
            ))
        }
        return type
    }
}

// MARK: - Client Certificate Type Extension

/// client_certificate_type extension (RFC 7250) — negotiates the format
/// of the certificate the *client* sends for client authentication.
public enum ClientCertificateTypeExtension: Sendable, TLSExtensionValue, Equatable {
    public static var extensionType: TLSExtensionType { .clientCertificateType }

    /// ClientHello variant: types the client can present, in preference order
    case offered([CertificateType])

    /// EncryptedExtensions variant: the type the server selected
    case selected(CertificateType)

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        switch self {
        case .offered(let types):
            return try CertificateTypeCodec.encodeOffered(types)
        case .selected(let type):
            return CertificateTypeCodec.encodeSelected(type)
        }
    }

    /// Decode ClientHello variant
    public static func decodeOffered(from data: [UInt8]) throws(TLSWireError) -> ClientCertificateTypeExtension {
        .offered(try CertificateTypeCodec.decodeOffered(from: data, extensionName: "client_certificate_type"))
    }

    /// Decode EncryptedExtensions variant
    public static func decodeSelected(from data: [UInt8]) throws(TLSWireError) -> ClientCertificateTypeExtension {
        .selected(try CertificateTypeCodec.decodeSelected(from: data, extensionName: "client_certificate_type"))
    }
}

// MARK: - Server Certificate Type Extension

/// server_certificate_type extension (RFC 7250) — negotiates the format
/// of the certificate the *server* sends for server authentication.
public enum ServerCertificateTypeExtension: Sendable, TLSExtensionValue, Equatable {
    public static var extensionType: TLSExtensionType { .serverCertificateType }

    /// ClientHello variant: types the client can validate, in preference order
    case offered([CertificateType])

    /// EncryptedExtensions variant: the type the server selected
    case selected(CertificateType)

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        switch self {
        case .offered(let types):
            return try CertificateTypeCodec.encodeOffered(types)
        case .selected(let type):
            return CertificateTypeCodec.encodeSelected(type)
        }
    }

    /// Decode ClientHello variant
    public static func decodeOffered(from data: [UInt8]) throws(TLSWireError) -> ServerCertificateTypeExtension {
        .offered(try CertificateTypeCodec.decodeOffered(from: data, extensionName: "server_certificate_type"))
    }

    /// Decode EncryptedExtensions variant
    public static func decodeSelected(from data: [UInt8]) throws(TLSWireError) -> ServerCertificateTypeExtension {
        .selected(try CertificateTypeCodec.decodeSelected(from: data, extensionName: "server_certificate_type"))
    }
}
