/// Concrete DTLS handshake-crypto construction for the package-wide provider.
///
/// Provider selection happens once at configuration time. The handshake core
/// receives immutable non-generic owners and never performs associated-type
/// dispatch while deriving traffic keys or hashing the transcript.

import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto
import DTLSHandshakeCore

extension TLSCryptoProvider {
    package static func dtlsPRFContext() -> DTLSPRFContext {
        DTLSPRFContext(
            hmacSHA256: { first, second, key in
                var hmac = TLSCryptoProvider.HMACSHA256(key: key.span)
                hmac.update(first.span)
                if let second {
                    hmac.update(second.span)
                }
                return hmac.finalize()
            },
            hmacSHA384: { first, second, key in
                var hmac = TLSCryptoProvider.HMACSHA384(key: key.span)
                hmac.update(first.span)
                if let second {
                    hmac.update(second.span)
                }
                return hmac.finalize()
            }
        )
    }

    package static func dtlsTranscriptContext() -> DTLSTranscriptContext {
        DTLSTranscriptContext(
            sha256: { message in
                var hash = TLSCryptoProvider.SHA256()
                hash.update(message.span)
                return hash.finalize()
            },
            sha384: { message in
                var hash = TLSCryptoProvider.SHA384()
                hash.update(message.span)
                return hash.finalize()
            }
        )
    }
}
