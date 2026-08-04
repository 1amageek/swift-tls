import Testing
import DTLSWireCore

@Test
func dtlsWebRTCProfileCarriesEMSAndRenegotiationInfo() throws {
    let clientHello = DTLSClientHello(
        random: [UInt8](repeating: 0x11, count: 32),
        extendedMasterSecret: true,
        renegotiationInfo: true
    )
    let decodedClientHello = try DTLSClientHello.decode(from: clientHello.encodeBytes())
    #expect(decodedClientHello.extendedMasterSecret)
    #expect(decodedClientHello.renegotiationInfo)

    let serverHello = DTLSServerHello(
        random: [UInt8](repeating: 0x22, count: 32),
        cipherSuite: .ecdheEcdsaWithAes128GcmSha256,
        extendedMasterSecret: true,
        renegotiationInfo: true
    )
    let decodedServerHello = try DTLSServerHello.decode(from: serverHello.encodeBytes())
    #expect(decodedServerHello.extendedMasterSecret)
    #expect(decodedServerHello.renegotiationInfo)
}

@Test
func dtlsWebRTCProfileRejectsMissingSecurityExtensionsAtWireBoundary() throws {
    let legacy = DTLSClientHello(
        random: [UInt8](repeating: 0x33, count: 32),
        extendedMasterSecret: false,
        renegotiationInfo: false
    )
    let decoded = try DTLSClientHello.decode(from: legacy.encodeBytes())
    #expect(!decoded.extendedMasterSecret)
    #expect(!decoded.renegotiationInfo)
}
