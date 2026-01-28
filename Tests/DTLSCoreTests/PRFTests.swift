/// Tests for TLS 1.2 PRF implementation

import Testing
import Foundation
@testable import DTLSCore

@Suite("PRF Tests")
struct PRFTests {

    @Test("PRF produces deterministic output")
    func prfDeterministic() {
        let secret = Data(repeating: 0xAB, count: 32)
        let seed = Data(repeating: 0xCD, count: 32)

        let result1 = PRF.compute(secret: secret, label: "test label", seed: seed, length: 48)
        let result2 = PRF.compute(secret: secret, label: "test label", seed: seed, length: 48)

        #expect(result1 == result2)
        #expect(result1.count == 48)
    }

    @Test("PRF output length is correct")
    func prfOutputLength() {
        let secret = Data(repeating: 0x01, count: 16)
        let seed = Data(repeating: 0x02, count: 16)

        for length in [12, 32, 48, 64, 128] {
            let result = PRF.compute(secret: secret, label: "test", seed: seed, length: length)
            #expect(result.count == length)
        }
    }

    @Test("PRF with different labels produces different output")
    func prfDifferentLabels() {
        let secret = Data(repeating: 0xAA, count: 32)
        let seed = Data(repeating: 0xBB, count: 32)

        let result1 = PRF.compute(secret: secret, label: "master secret", seed: seed, length: 48)
        let result2 = PRF.compute(secret: secret, label: "key expansion", seed: seed, length: 48)

        #expect(result1 != result2)
    }

    @Test("PRF with different secrets produces different output")
    func prfDifferentSecrets() {
        let secret1 = Data(repeating: 0x01, count: 32)
        let secret2 = Data(repeating: 0x02, count: 32)
        let seed = Data(repeating: 0xCC, count: 32)

        let result1 = PRF.compute(secret: secret1, label: "test", seed: seed, length: 48)
        let result2 = PRF.compute(secret: secret2, label: "test", seed: seed, length: 48)

        #expect(result1 != result2)
    }

    @Test("PRF SHA-384 produces deterministic output")
    func prfSHA384Deterministic() {
        let secret = Data(repeating: 0xAB, count: 48)
        let seed = Data(repeating: 0xCD, count: 32)

        let result1 = PRF.computeSHA384(secret: secret, label: "test label", seed: seed, length: 48)
        let result2 = PRF.computeSHA384(secret: secret, label: "test label", seed: seed, length: 48)

        #expect(result1 == result2)
        #expect(result1.count == 48)
    }

    @Test("PRF SHA-256 and SHA-384 produce different output")
    func prfDifferentHash() {
        let secret = Data(repeating: 0xAB, count: 32)
        let seed = Data(repeating: 0xCD, count: 32)

        let sha256 = PRF.compute(secret: secret, label: "test", seed: seed, length: 48)
        let sha384 = PRF.computeSHA384(secret: secret, label: "test", seed: seed, length: 48)

        #expect(sha256 != sha384)
    }
}
