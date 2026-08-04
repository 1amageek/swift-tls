/// Direction-safe SRTP master keying material derived from DTLS.

import DTLSWireCore

/// Per-association master key and salt values for the local and remote directions.
///
/// Arrays own the one-time exporter split. Packet processing must derive and retain
/// SRTP session keys once; it must not repeat this conversion per packet.
public struct DTLSSRTPKeyingMaterial: Sendable, Equatable {
    public let protectionProfile: DTLSSRTPProtectionProfile
    public let localMasterKey: [UInt8]
    public let remoteMasterKey: [UInt8]
    public let localMasterSalt: [UInt8]
    public let remoteMasterSalt: [UInt8]

    init(
        protectionProfile: DTLSSRTPProtectionProfile,
        localMasterKey: [UInt8],
        remoteMasterKey: [UInt8],
        localMasterSalt: [UInt8],
        remoteMasterSalt: [UInt8]
    ) {
        self.protectionProfile = protectionProfile
        self.localMasterKey = localMasterKey
        self.remoteMasterKey = remoteMasterKey
        self.localMasterSalt = localMasterSalt
        self.remoteMasterSalt = remoteMasterSalt
    }

    static func split(
        _ bytes: [UInt8],
        wireProtectionProfile: SRTPProtectionProfile,
        localIsClient: Bool
    ) -> DTLSSRTPKeyingMaterial? {
        guard wireProtectionProfile == .aes128CMHMACSHA180, bytes.count == 60 else {
            return nil
        }
        let clientKey = Array(bytes[0..<16])
        let serverKey = Array(bytes[16..<32])
        let clientSalt = Array(bytes[32..<46])
        let serverSalt = Array(bytes[46..<60])
        return DTLSSRTPKeyingMaterial(
            protectionProfile: DTLSSRTPProtectionProfile(
                wireProfile: wireProtectionProfile
            ),
            localMasterKey: localIsClient ? clientKey : serverKey,
            remoteMasterKey: localIsClient ? serverKey : clientKey,
            localMasterSalt: localIsClient ? clientSalt : serverSalt,
            remoteMasterSalt: localIsClient ? serverSalt : clientSalt
        )
    }
}
