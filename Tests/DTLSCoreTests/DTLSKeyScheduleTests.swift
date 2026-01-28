/// Tests for DTLS 1.2 Key Schedule

import Testing
import Foundation
@testable import DTLSCore

@Suite("DTLSKeySchedule Tests")
struct DTLSKeyScheduleTests {

    @Test("Key schedule derives master secret and key block")
    func deriveKeyBlock() throws {
        var schedule = DTLSKeySchedule(cipherSuite: .ecdheEcdsaWithAes128GcmSha256)

        let preMasterSecret = Data(repeating: 0xAA, count: 32)
        let clientRandom = Data(repeating: 0xBB, count: 32)
        let serverRandom = Data(repeating: 0xCC, count: 32)

        schedule.deriveMasterSecret(
            preMasterSecret: preMasterSecret,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        let keyBlock = try schedule.deriveKeyBlock()

        // AES-128-GCM: 16-byte keys, 4-byte IVs
        #expect(keyBlock.clientWriteKey.count == 16)
        #expect(keyBlock.serverWriteKey.count == 16)
        #expect(keyBlock.clientWriteIV.count == 4)
        #expect(keyBlock.serverWriteIV.count == 4)

        // Client and server keys should differ
        #expect(keyBlock.clientWriteKey != keyBlock.serverWriteKey)
        #expect(keyBlock.clientWriteIV != keyBlock.serverWriteIV)
    }

    @Test("Key schedule produces consistent results")
    func deterministic() throws {
        let preMasterSecret = Data(repeating: 0x11, count: 32)
        let clientRandom = Data(repeating: 0x22, count: 32)
        let serverRandom = Data(repeating: 0x33, count: 32)

        var schedule1 = DTLSKeySchedule(cipherSuite: .ecdheEcdsaWithAes128GcmSha256)
        schedule1.deriveMasterSecret(
            preMasterSecret: preMasterSecret,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        var schedule2 = DTLSKeySchedule(cipherSuite: .ecdheEcdsaWithAes128GcmSha256)
        schedule2.deriveMasterSecret(
            preMasterSecret: preMasterSecret,
            clientRandom: clientRandom,
            serverRandom: serverRandom
        )

        let kb1 = try schedule1.deriveKeyBlock()
        let kb2 = try schedule2.deriveKeyBlock()

        #expect(kb1.clientWriteKey == kb2.clientWriteKey)
        #expect(kb1.serverWriteKey == kb2.serverWriteKey)
        #expect(kb1.clientWriteIV == kb2.clientWriteIV)
        #expect(kb1.serverWriteIV == kb2.serverWriteIV)
    }

    @Test("Key schedule throws without master secret")
    func throwsWithoutMasterSecret() {
        let schedule = DTLSKeySchedule(cipherSuite: .ecdheEcdsaWithAes128GcmSha256)
        #expect(throws: DTLSError.self) {
            try schedule.deriveKeyBlock()
        }
    }

    @Test("Verify data computation")
    func verifyData() throws {
        var schedule = DTLSKeySchedule(cipherSuite: .ecdheEcdsaWithAes128GcmSha256)
        schedule.deriveMasterSecret(
            preMasterSecret: Data(repeating: 0xAA, count: 32),
            clientRandom: Data(repeating: 0xBB, count: 32),
            serverRandom: Data(repeating: 0xCC, count: 32)
        )

        let handshakeHash = Data(repeating: 0xDD, count: 32)
        let clientVerify = try schedule.computeVerifyData(
            label: "client finished",
            handshakeHash: handshakeHash
        )
        let serverVerify = try schedule.computeVerifyData(
            label: "server finished",
            handshakeHash: handshakeHash
        )

        #expect(clientVerify.count == 12)
        #expect(serverVerify.count == 12)
        #expect(clientVerify != serverVerify)
    }

    @Test("AES-256-GCM key schedule")
    func aes256KeyBlock() throws {
        var schedule = DTLSKeySchedule(cipherSuite: .ecdheEcdsaWithAes256GcmSha384)
        schedule.deriveMasterSecret(
            preMasterSecret: Data(repeating: 0xAA, count: 48),
            clientRandom: Data(repeating: 0xBB, count: 32),
            serverRandom: Data(repeating: 0xCC, count: 32)
        )

        let keyBlock = try schedule.deriveKeyBlock()

        // AES-256-GCM: 32-byte keys, 4-byte IVs
        #expect(keyBlock.clientWriteKey.count == 32)
        #expect(keyBlock.serverWriteKey.count == 32)
        #expect(keyBlock.clientWriteIV.count == 4)
        #expect(keyBlock.serverWriteIV.count == 4)
    }
}
