import TLS
import P2PCoreBytes
import SSLCrypto

@main
struct FacadeValidationCommand {
    static func main() {
        do {
            // Keep the primitive provider in the executable link graph. The
            // facade's provider is intentionally supplied by swift-ssl.
            _ = MemoryLayout<SHA256Context>.size
            let client = try TLSClient(
                configuration: TLSConfiguration(
                    serverName: "validation.invalid",
                    verifyPeer: false
                )
            )
            let clientHello = try client.startHandshake()
            guard !clientHello.isEmpty else {
                throw ValidationFailure.emptyClientHello
            }

            var rejectedMalformedRecord = false
            do {
                _ = try client.receive([0xFF].span)
            } catch {
                rejectedMalformedRecord = true
            }
            guard rejectedMalformedRecord else {
                throw ValidationFailure.malformedRecordAccepted
            }
            print("swift-tls facade validation: ok")
        } catch {
            // Embedded Swift does not support generic interpolation of any Error.
            print("swift-tls facade validation: failed")
            fatalError("swift-tls facade validation failed")
        }
    }
}

private enum ValidationFailure: Error {
    case emptyClientHello
    case malformedRecordAccepted
}
