// swift-tools-version: 6.2
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

let package = Package(
    name: "swift-tls",
    platforms: [
        .macOS(.v26), .iOS(.v26), .tvOS(.v26),
        .watchOS(.v26), .visionOS(.v26),
    ],
    products: [
        // ---- Tier-1 facade (the default `import TLS`) ----
        .library(name: "TLS", targets: ["TLS"]),
        // ---- Tier-3 pure wire codecs (separate opt-in import) ----
        .library(name: "TLSWire", targets: ["TLSWireCore"]),
        .library(name: "DTLSWire", targets: ["DTLSWireCore"]),
    ],
    dependencies: [
        // Crypto-provider unification (embedded-first-api.md §2.2): swift-tls
        // specialises its generic cores at the stack-wide shared provider via the
        // local `TLSCryptoProvider` composite — `P2PCrypto.DefaultCryptoProvider`
        // for every primitive EXCEPT the two ECDSA signature schemes, which use the
        // DER encoding TLS 1.3 CertificateVerify requires (RFC 8446 §4.2.3). This is
        // UNIFORM with swift-quic's `QUICCryptoProvider`.
        //
        // This is now possible because swift-p2p-crypto's host `FoundationCryptoProvider`
        // sources `Crypto` from the SAME `apple/swift-crypto` identity that
        // swift-certificates uses (range `3.12.3..<5.0.0`), with the vendored BoringSSL
        // given a DISTINCT identity (`p2p-boringssl`). There is therefore one coherent
        // `swift-crypto` in the graph and no `.macOS(.v26)` floor is forced onto
        // swift-certificates — the stale rejection that previously blocked this is gone.
        // The swift-crypto range below mirrors swift-p2p-crypto/swift-quic so the whole
        // graph agrees on one version.
        .package(path: "../swift-p2p-core"),
        .package(path: "../swift-p2p-crypto"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.12.3"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.1"),
    ],
    targets: [
        // ---- Embedded-clean wire codec (dual-build: host + Embedded) ----
        // Tier-3 product `TLSWire` (pure codec over ByteReader/ByteWriter).
        .target(
            name: "TLSWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/TLSWireCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean TLS 1.3 key schedule (dual-build: host + Embedded) ----
        // package-visible facade internal (generic over C: CryptoProvider).
        .target(
            name: "TLSCryptoCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                "TLSWireCore",
            ],
            path: "Sources/TLSCryptoCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean TLS 1.3 handshake FSM (dual-build: host + Embedded) ----
        .target(
            name: "TLSHandshakeCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                "TLSWireCore",
                "TLSCryptoCore",
            ],
            path: "Sources/TLSHandshakeCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean DTLS wire codec (dual-build: host + Embedded) ----
        // Tier-3 product `DTLSWire`.
        .target(
            name: "DTLSWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                "TLSWireCore",
            ],
            path: "Sources/DTLSWireCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean DTLS 1.2 handshake FSM + key schedule (dual-build) ----
        .target(
            name: "DTLSHandshakeCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                "TLSWireCore",
                "DTLSWireCore",
            ],
            path: "Sources/DTLSHandshakeCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean TLS record-layer codec + AEAD protector (dual-build) ----
        .target(
            name: "TLSRecordCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                "TLSWireCore",
            ],
            path: "Sources/TLSRecordCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean DTLS record-layer types (anti-replay, errors, AEAD protector) ----
        .target(
            name: "DTLSRecordCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/DTLSRecordCore",
            swiftSettings: coreSettings
        ),
        // ---- Host engine: TLS 1.3 handshake + crypto/X509 (package-visible) ----
        .target(
            name: "TLSCore",
            dependencies: [
                "TLSWireCore",
                "TLSCryptoCore",
                "TLSHandshakeCore",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                // Unified provider: the host adapter specialises every generic
                // engine at the local `TLSCryptoProvider` composite (= shared
                // `DefaultCryptoProvider` + DER-ECDSA override), replacing the
                // deleted standalone `TLSProvider` aggregate.
                .product(name: "P2PCrypto", package: "swift-p2p-crypto"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Sources/TLSCore"
        ),
        // ---- Host record engine behind TLSClient/TLSServer (package-visible) ----
        .target(
            name: "TLSRecord",
            dependencies: [
                "TLSCore",
                "TLSRecordCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/TLSRecord"
        ),
        // ---- Host DTLS engine (package-visible) ----
        .target(
            name: "DTLSCore",
            dependencies: [
                "TLSCore",
                "DTLSWireCore",
                "DTLSHandshakeCore",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            path: "Sources/DTLSCore"
        ),
        // ---- Host DTLS record engine behind DTLSClient/DTLSServer (package-visible) ----
        .target(
            name: "DTLSRecord",
            dependencies: [
                "DTLSCore",
                "DTLSRecordCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/DTLSRecord"
        ),
        // ---- Tier-1 facade: TLSClient/TLSServer/DTLSClient/DTLSServer ----
        // The only public-facing module a normal user imports. Non-generic, fixed
        // to DefaultCryptoProvider, [UInt8]/Span<UInt8> currency, one TLSError.
        .target(
            name: "TLS",
            dependencies: [
                "TLSRecord",
                "DTLSRecord",
                "TLSCore",
                "DTLSCore",
            ],
            path: "Sources/TLS"
        ),
        .testTarget(
            name: "TLSCoreTests",
            dependencies: [
                "TLS",
                "TLSCore",
                "TLSRecord",
                "TLSCryptoCore",
                // Tier-3 wire/record cores: the engine no longer @_exports them, so
                // tests that reference wire types import them explicitly.
                "TLSWireCore",
                "TLSRecordCore",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/TLSCoreTests"
        ),
        .testTarget(
            name: "TLSRecordTests",
            dependencies: [
                "TLS",
                "TLSRecord",
                "TLSCore",
                "TLSRecordCore",
                "TLSWireCore",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/TLSRecordTests"
        ),
        .testTarget(
            name: "DTLSCoreTests",
            dependencies: [
                "TLS", "DTLSCore", "TLSCore",
                "TLSWireCore", "DTLSWireCore", "DTLSHandshakeCore", "DTLSRecordCore",
            ],
            path: "Tests/DTLSCoreTests"
        ),
        .testTarget(
            name: "DTLSRecordTests",
            dependencies: [
                "TLS",
                "DTLSRecord",
                "DTLSCore",
                "DTLSRecordCore",
                "TLSWireCore",
                "DTLSWireCore",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/DTLSRecordTests"
        ),
    ]
)
