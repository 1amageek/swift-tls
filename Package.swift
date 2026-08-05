// swift-tools-version: 6.4
import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO for the
// Embedded-clean cores. Lifetimes is enabled in BOTH modes because Span-returning
// members of the P2PCoreBytes dependency require @_lifetime.
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// The canonical Stream/QUIC/DTLS mechanisms are backed directly by swift-ssl on
// every target. This package owns only session configuration and transport
// adapters; protocol state machines and wire/record mechanisms live in swift-ssl.
let cryptoProviderDependencies: [Target.Dependency] = {
    let d: [Target.Dependency] = [
        .product(name: "P2PCoreCrypto", package: "swift-ssl"),
        .product(name: "P2PCoreBytes", package: "swift-ssl"),
        .product(name: "P2PCoreDER", package: "swift-p2p-core"),
        .product(name: "P2PCrypto", package: "swift-p2p-core"),
        .product(name: "SSLCore", package: "swift-ssl"),
        .product(name: "SSLCrypto", package: "swift-ssl"),
        .product(name: "SSLDTLS", package: "swift-ssl"),
        .product(name: "DTLSRecord", package: "swift-ssl"),
        .product(name: "DTLSHandshake", package: "swift-ssl"),
        .product(name: "TLSWire", package: "swift-ssl"),
    ]
    return d
}()

// The Tier-1 facade's dependencies are the same on Native, WASM, and Embedded.
// Stream TLS and DTLS 1.2 both use swift-ssl-owned mechanisms; this package only
// supplies session configuration, the concrete crypto strategy, and the
// caller-side Mutex.
let facadeDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        "TLSCryptoProvider",
        .product(name: "TLSWire", package: "swift-ssl"),
        .product(name: "DTLSWire", package: "swift-ssl"),
        .product(name: "DTLSHandshake", package: "swift-ssl"),
        .product(name: "DTLSRecord", package: "swift-ssl"),
        .product(name: "SSLDTLS", package: "swift-ssl"),
        .product(name: "P2PCoreBytes", package: "swift-ssl"),
        .product(name: "P2PCoreCrypto", package: "swift-ssl"),
        .product(name: "P2PCoreDER", package: "swift-p2p-core"),
    ]
    d += [
        .product(name: "SSLCore", package: "swift-ssl"),
        .product(name: "SSLCrypto", package: "swift-ssl"),
        .product(name: "SSLASN1", package: "swift-ssl"),
        .product(name: "SSLX509", package: "swift-ssl"),
        .product(name: "SSLTLS", package: "swift-ssl"),
        .product(name: "SSLQUIC", package: "swift-ssl"),
    ]
    return d
}()

let package = Package(
    // This package owns the public session contracts. Its package identity and
    // repository URL are intentionally distinct from Apple's `swift-tls`
    // package, which has a different scope and is not a replacement for this API.
    name: "swift-tls-sessions",
    platforms: [
        .macOS(.v26), .iOS(.v26), .tvOS(.v26),
        .watchOS(.v26), .visionOS(.v26),
    ],
    products: [
        // ---- Tier-1 facade (the default `import TLS`) ----
        .library(name: "TLS", targets: ["TLS"]),
        // ---- QUIC TLS session boundary ----
        .library(name: "QUICTLS", targets: ["QUICTLS"]),
        // ---- Tier-3 pure wire codecs (separate opt-in import) ----
    ],
    dependencies: [
        .package(url: "https://github.com/1amageek/swift-ssl.git", branch: "main"),
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", branch: "main"),
    ],
    targets: [
        // ---- Unified Pure Swift crypto provider (dual-build: host + Embedded) ----
        .target(
            name: "TLSCryptoProvider",
            dependencies: cryptoProviderDependencies,
            path: "Sources/TLSCryptoProvider",
            swiftSettings: coreSettings
        ),
        // ---- Tier-1 facade: TLSClient/TLSServer/DTLSClient/DTLSServer ----
        // The only public-facing stream/DTLS module a normal user imports. It
        // is fixed to `TLSCryptoProvider`, uses [UInt8]/Span<UInt8> at the
        // compatibility boundary, and exposes one typed error family.
        // All targets use the same swift-ssl certificate and signing path. The
        // platform implementation may specialize allocation or synchronization,
        // but the session contract and ownership semantics do not change.
        .target(
            name: "TLS",
            dependencies: facadeDependencies,
            path: "Sources/TLS",
            exclude: [
                "CONTEXT.md",
            ],
            swiftSettings: coreSettings
        ),
        .target(
            name: "QUICTLS",
            dependencies: [
                .product(name: "SSLCore", package: "swift-ssl"),
                .product(name: "SSLQUIC", package: "swift-ssl"),
            ],
            path: "Sources/QUICTLS",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "TLSCanonicalTests",
            dependencies: [
                "TLS",
                "TLSCryptoProvider",
                .product(name: "SSLDTLS", package: "swift-ssl"),
                .product(name: "DTLSRecord", package: "swift-ssl"),
            ],
            path: "Tests/TLSCanonicalTests"
        ),
    ]
)
