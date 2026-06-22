/// DTLS Cookie Secret Provider (RFC 6347 §4.2.1)
///
/// Supplies the server-side HMAC secret used to mint and verify stateless
/// HelloVerifyRequest cookies. The secret is process-global (shared across all
/// connections) and rotates over time so that the cookie check does NOT require
/// per-connection state to exist before the cookie is validated.
///
/// ## Why process-global
///
/// A per-connection secret allocated on first ClientHello defeats the purpose of
/// the cookie exchange: it forces the server to allocate state for an
/// unauthenticated peer (the very DoS the cookie is meant to prevent) and means a
/// ClientHello carrying a cookie cannot be validated unless matching per-connection
/// state happens to exist. A shared, rotating secret lets the server verify any
/// presented cookie statelessly.
///
/// ## Rotation
///
/// Two secrets are kept — `current` and `previous`. Minting always uses `current`.
/// Verification accepts a cookie that matches EITHER secret, so cookies issued just
/// before a rotation remain valid for one rotation period (avoiding spurious
/// failures at the boundary). Rotation happens lazily when the rotation interval
/// has elapsed since the current secret was generated.

import Foundation
import Crypto
import Synchronization
import TLSCore

/// Process-global rotating secret used to mint and verify DTLS cookies.
public final class DTLSCookieSecretProvider: Sendable {
    /// The shared instance used by the DTLS server handshake handler.
    public static let shared = DTLSCookieSecretProvider()

    /// How long a secret remains the `current` minting secret before rotation.
    /// A previously-current secret stays valid for verification for one further
    /// interval, so a cookie is usable for up to two intervals after issuance.
    private static let rotationInterval: Duration = .seconds(60)

    private struct SecretState: Sendable {
        var current: SymmetricKey
        var previous: SymmetricKey?
        var currentGeneratedAt: ContinuousClock.Instant
    }

    private let state: Mutex<SecretState>
    private let clock = ContinuousClock()

    /// - Parameter initialSecret: The bytes of the initial current secret. When
    ///   `nil`, a fresh 32-byte secret is generated.
    public init(initialSecret: Data? = nil) {
        let secretBytes: Data
        if let initialSecret {
            secretBytes = initialSecret
        } else {
            // Draw the initial secret from CryptoKit's non-throwing CSPRNG-backed
            // SymmetricKey, so no throwing RNG API (and thus no `try!`) is involved.
            secretBytes = Self.makeSecretBytes()
        }
        self.state = Mutex(
            SecretState(
                current: SymmetricKey(data: secretBytes),
                previous: nil,
                currentGeneratedAt: ContinuousClock().now
            )
        )
    }

    /// Generate a cookie for the given ClientHello binding material using the
    /// current secret.
    public func makeCookie(bindingMaterial: Data) -> Data {
        let secret = state.withLock { s -> SymmetricKey in
            rotateIfNeededLocked(&s)
            return s.current
        }
        let mac = HMAC<SHA256>.authenticationCode(for: bindingMaterial, using: secret)
        return Data(mac)
    }

    /// Verify a cookie against the binding material, accepting either the current
    /// or the previous (just-rotated) secret. Comparison is constant-time.
    public func verifyCookie(_ cookie: Data, bindingMaterial: Data) -> Bool {
        let (current, previous) = state.withLock { s -> (SymmetricKey, SymmetricKey?) in
            rotateIfNeededLocked(&s)
            return (s.current, s.previous)
        }

        let expectedCurrent = Data(HMAC<SHA256>.authenticationCode(for: bindingMaterial, using: current))
        if constantTimeEqual(expectedCurrent, cookie) {
            return true
        }
        if let previous {
            let expectedPrevious = Data(HMAC<SHA256>.authenticationCode(for: bindingMaterial, using: previous))
            if constantTimeEqual(expectedPrevious, cookie) {
                return true
            }
        }
        return false
    }

    // MARK: - Private

    private func rotateIfNeededLocked(_ s: inout SecretState) {
        let now = clock.now
        if now - s.currentGeneratedAt >= Self.rotationInterval {
            s.previous = s.current
            s.current = SymmetricKey(data: Self.makeSecretBytes())
            s.currentGeneratedAt = now
        }
    }

    private static func makeSecretBytes() -> Data {
        // CryptoKit's SymmetricKey(size:) draws from the system CSPRNG and does not
        // throw. Use it directly so we never resort to `try!` on a throwing API.
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { Data($0) }
    }
}
