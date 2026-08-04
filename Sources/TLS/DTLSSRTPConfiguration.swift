/// Required DTLS-SRTP negotiation policy for a DTLS association.

import DTLSWireCore

/// A validated, ordered set of SRTP profiles that the endpoint can implement.
///
/// Supplying this value makes `use_srtp` negotiation mandatory. Omitting it from
/// ``DTLSConfiguration`` keeps the association in ordinary DTLS application-data
/// mode. MKI negotiation is intentionally not exposed until the SRTP context owns
/// key rotation; wire decoding still preserves MKI values and rejects mismatches.
public struct DTLSSRTPConfiguration: Sendable, Equatable {
    public let protectionProfiles: [DTLSSRTPProtectionProfile]

    public init(
        protectionProfiles: [DTLSSRTPProtectionProfile]
    ) throws(TLSError) {
        guard !protectionProfiles.isEmpty else {
            throw .invalidConfiguration(reason: "DTLS-SRTP requires at least one protection profile")
        }
        for index in protectionProfiles.indices {
            guard !protectionProfiles[..<index].contains(protectionProfiles[index]) else {
                throw .invalidConfiguration(reason: "DTLS-SRTP protection profiles must be unique")
            }
        }
        guard protectionProfiles.allSatisfy({ $0 == .aes128CMHMACSHA180 }) else {
            throw .invalidConfiguration(
                reason: "Only SRTP_AES128_CM_HMAC_SHA1_80 is implemented"
            )
        }
        self.protectionProfiles = protectionProfiles
    }

    var wireProtectionProfiles: [DTLSWireCore.SRTPProtectionProfile] {
        var result: [DTLSWireCore.SRTPProtectionProfile] = []
        result.reserveCapacity(protectionProfiles.count)
        for profile in protectionProfiles {
            result.append(profile.wireProfile)
        }
        return result
    }
}
