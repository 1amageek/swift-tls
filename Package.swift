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
        // NOTE on the crypto provider:
        // The Embedded-first design wanted swift-tls to specialise its cores at
        // `P2PCrypto.DefaultCryptoProvider`. That is NOT possible while swift-tls
        // depends on swift-certificates: swift-p2p-crypto's `P2PCrypto` pulls a
        // VENDORED swift-crypto floored at .macOS(.v26), and a path dependency wins
        // SPM identity resolution over the remote `apple/swift-crypto`. The
        // vendored v26 `Crypto` product then cannot satisfy swift-certificates
        // (whose targets support .macOS(.v12)) — SPM rejects it. swift-tls
        // therefore keeps the remote `apple/swift-crypto` (low floor) and builds
        // its single unified `TLSProvider` over it. The duplicate standalone
        // provider `TLSFoundationProvider` is still deleted (one provider now).
        .package(path: "../swift-p2p-core"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
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
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/TLSRecordTests"
        ),
        .testTarget(
            name: "DTLSCoreTests",
            dependencies: ["TLS", "DTLSCore", "TLSCore"],
            path: "Tests/DTLSCoreTests"
        ),
        .testTarget(
            name: "DTLSRecordTests",
            dependencies: [
                "TLS",
                "DTLSRecord",
                "DTLSCore",
                "DTLSRecordCore",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Tests/DTLSRecordTests"
        ),
    ]
)
