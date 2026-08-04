import Testing
import TLSCryptoProvider
import DTLSRecordCore

@Test
func pureSwiftProviderSignsAndVerifies() throws {
    let signing = try TLSCryptoProvider.P256Signature.generateSigningKey()
    let verifying = TLSCryptoProvider.P256Signature.verifyingKey(for: signing)
    let message = Array("canonical swift-ssl".utf8)
    let signature = try TLSCryptoProvider.P256Signature.sign(message.span, with: signing)

    let valid = signature.withUnsafeBufferPointer { signatureBuffer in
        message.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P256Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(valid)

    var modified = message
    modified[0] ^= 1
    let modifiedValid = signature.withUnsafeBufferPointer { signatureBuffer in
        modified.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P256Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(!modifiedValid)
}

@Test
func pureSwiftProviderP384SignsAndVerifies() throws {
    let signing = try TLSCryptoProvider.P384Signature.generateSigningKey()
    let verifying = TLSCryptoProvider.P384Signature.verifyingKey(for: signing)
    let message = Array("canonical swift-ssl P-384".utf8)
    let signature = try TLSCryptoProvider.P384Signature.sign(message.span, with: signing)
    let valid = signature.withUnsafeBufferPointer { signatureBuffer in
        message.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P384Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(valid)

    var modified = message
    modified[0] ^= 1
    let modifiedValid = signature.withUnsafeBufferPointer { signatureBuffer in
        modified.withUnsafeBufferPointer { messageBuffer in
            TLSCryptoProvider.P384Signature.isValid(
                signature: Span(_unsafeElements: signatureBuffer),
                for: Span(_unsafeElements: messageBuffer),
                with: verifying
            )
        }
    }
    #expect(!modifiedValid)
}

@Test
func pureSwiftProviderRoundTripsAEAD() throws {
    let key = [UInt8](repeating: 0x42, count: 16)
    let nonce = [UInt8](repeating: 0x24, count: 12)
    let aad = Array("header".utf8)
    let plaintext = Array("payload".utf8)
    let aead = try TLSCryptoProvider.makeAESGCM128(key: key.span)
    let ciphertext = try aead.seal(plaintext.span, nonce: nonce.span, aad: aad.span)
    let opened = try aead.open(ciphertext.span, nonce: nonce.span, aad: aad.span)
    #expect(opened == plaintext)
}

@Test
func pureSwiftProviderRoundTripsDTLSRecordProtection() throws {
    let key = [UInt8](repeating: 0x42, count: 16)
    let fixedIV = [UInt8](repeating: 0x24, count: 4)
    let context = try TLSCryptoProvider.makeDTLSAES128RecordProtectionContext(
        key: key,
        fixedIV: fixedIV
    )
    let plaintext = Array("dtls record through SSLDTLS".utf8)
    let explicitNonce: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 1]
    let aad = [UInt8](repeating: 0xA5, count: 13)

    let ciphertext = try context.seal(
        plaintext: plaintext,
        explicitNonce: explicitNonce,
        aad: aad
    )
    let opened = try context.open(ciphertext: ciphertext, aad: aad)
    #expect(opened == plaintext)

    var tampered = ciphertext
    tampered[tampered.index(before: tampered.endIndex)] ^= 1
    #expect(throws: DTLSRecordProtectionError.self) {
        _ = try context.open(ciphertext: tampered, aad: aad)
    }
}
