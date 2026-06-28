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

// The unified `TLSCryptoProvider` target's dependencies. On host it adds the
// swift-crypto `Crypto` product (the `#else` DER-ECDSA path uses `derRepresentation`);
// under Embedded that path is `#if`-excluded and the BoringSSL backend + `P2PCoreDER`
// supply the DER encoding, so `Crypto` is dropped to keep the Embedded build free of
// the non-Embedded swift-crypto module. This mirrors the `P2PCrypto` umbrella's own
// conditional backend dependency.
let cryptoProviderDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        .product(name: "P2PCrypto", package: "swift-p2p-crypto"),
        .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
        .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
        .product(name: "P2PCoreDER", package: "swift-p2p-core"),
    ]
    if !embeddedEnabled {
        d.append(.product(name: "Crypto", package: "swift-crypto"))
    }
    return d
}()

// The Tier-1 facade's dependencies. The cored Embedded-clean engines + the unified
// provider + the Embedded cert/sign strategy are present in BOTH builds. The host
// strategy bridges (X.509 + signing) live in TLSCore / DTLSCore / TLSRecord /
// DTLSRecord (Foundation/swift-crypto/X509-bound); they are dropped under Embedded,
// where the facade uses the `P2PCoreDER` raw-public-key strategy instead
// (`#if canImport(Foundation)` gates the source accordingly).
let facadeDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        "TLSEngineCore",
        "DTLSEngineCore",
        "TLSCryptoProvider",
        // The Embedded cert/sign strategy specialises these cores at the provider.
        "TLSCryptoCore",
        "DTLSHandshakeCore",
        "TLSWireCore",
        "DTLSWireCore",
        .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
        .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
        .product(name: "P2PCoreDER", package: "swift-p2p-core"),
    ]
    if !embeddedEnabled {
        d += [
            // Host strategy bridges (X.509 trust + signing for TLS; ECDHE +
            // sign/verify + cookie HMAC for DTLS) live in TLSCore / DTLSCore,
            // gated `#if canImport(Foundation)`.
            "TLSCore",
            "DTLSCore",
            // TLSRecord is retained only for the legacy error mapping.
            "TLSRecord",
            // DTLSRecord is retained as the package legacy host engine for the
            // DTLSRecord-level security tests; the facade no longer wraps it.
            "DTLSRecord",
        ]
    }
    return d
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
        // This is now possible because swift-p2p-crypto's host `FoundationEssentialsCryptoProvider`
        // sources `Crypto` from the SAME `apple/swift-crypto` identity that
        // swift-certificates uses (range `3.12.3..<5.0.0`), with vendored BoringSSL
        // wired behind renamed local C targets. There is therefore one coherent
        // `swift-crypto` in the graph and no `.macOS(.v26)` floor is forced onto
        // swift-certificates — the stale rejection that previously blocked this is gone.
        // The swift-crypto range below mirrors swift-p2p-crypto/swift-quic so the whole
        // graph agrees on one version.
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", from: "0.2.1"),
        .package(url: "https://github.com/1amageek/swift-p2p-crypto.git", from: "0.1.1"),
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
        // ---- Embedded-clean TLS/DTLS sans-IO connection engine (dual-build) ----
        // The cored orchestrator: drives the handshake FSMs (TLSClientHandshake /
        // TLSClientAuthMachine / TLSServerHandshake / DTLS*) through the record
        // protector, sans-IO, caller-locked, generic over `C: CryptoProvider`.
        // X.509 trust + CertificateVerify signing are INJECTED as closures in
        // `TLSEngineConfiguration<C>` (the facade host strategy fills them).
        // Embedded-clean: no Foundation/`any`/`Mutex`/`ContinuousClock`/X509.
        .target(
            name: "TLSEngineCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                "TLSWireCore",
                "TLSCryptoCore",
                "TLSHandshakeCore",
                "TLSRecordCore",
                "DTLSWireCore",
                "DTLSHandshakeCore",
                "DTLSRecordCore",
            ],
            path: "Sources/TLSEngineCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean DTLS 1.2 sans-IO connection engine (dual-build) ----
        // The cored DTLS orchestrator: drives the DTLS handshake FSMs
        // (DTLSClientHandshake / DTLSServerHandshake) through the value-type record
        // layer (epoch + 48-bit seq + anti-replay + AEAD), sans-IO, caller-locked,
        // generic over `C: CryptoProvider`. ECDHE + ServerKeyExchange/CertificateVerify
        // signing/verification + the HelloVerifyRequest cookie HMAC are INJECTED as
        // closures in `DTLSEngineConfiguration<C>` (the facade host strategy fills
        // them). Embedded-clean: no Foundation/`any`/`Mutex`/`ContinuousClock`/X509.
        .target(
            name: "DTLSEngineCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                "TLSWireCore",
                "DTLSWireCore",
                "DTLSHandshakeCore",
                "DTLSRecordCore",
            ],
            path: "Sources/DTLSEngineCore",
            swiftSettings: coreSettings
        ),
        // ---- Unified crypto provider (dual-build: host + Embedded) ----
        // The SINGLE place that imports `P2PCrypto`. `TLSCryptoProvider` = the
        // shared `DefaultCryptoProvider` for every primitive EXCEPT the two ECDSA
        // signature schemes, which are DER-encoded for the TLS 1.3 CertificateVerify
        // wire (RFC 8446 §4.2.3). The DER override is dual-built: host uses
        // `TLSDERP256/384Signature` (swift-crypto `derRepresentation`); Embedded uses
        // `EmbeddedDERP256/384Signature` (BoringSSL raw `r||s` + a `P2PCoreDER` DER
        // wrapper, byte-identical to the host output). Embedded-clean.
        .target(
            name: "TLSCryptoProvider",
            dependencies: cryptoProviderDependencies,
            path: "Sources/TLSCryptoProvider",
            swiftSettings: coreSettings
        ),
        // ---- Host engine: TLS 1.3 handshake + crypto/X509 (package-visible) ----
        .target(
            name: "TLSCore",
            dependencies: [
                "TLSWireCore",
                "TLSCryptoCore",
                "TLSHandshakeCore",
                // The cored sans-IO engine the facade drives. TLSCore provides the
                // HOST strategy bridge (X.509 trust + signing) that fills the
                // engine's injected seams (`#if canImport(Foundation)`).
                "TLSEngineCore",
                // Unified provider: `TLSCryptoProvider` (the shared
                // `DefaultCryptoProvider` + DER-ECDSA override) now lives in its own
                // Embedded-clean target. The host adapter imports it to specialise
                // every generic engine at it.
                "TLSCryptoProvider",
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
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
                // The cored sans-IO DTLS engine the facade drives. DTLSCore provides
                // the HOST strategy bridge (ECDHE + sign/verify + cookie HMAC) that
                // fills the engine's injected seams (`#if canImport(Foundation)`).
                "DTLSEngineCore",
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
        // ---- Tier-1 facade: TLSClient/TLSServer/DTLSClient/DTLSServer ----
        // The only public-facing module a normal user imports. Non-generic, fixed to
        // `TLSCryptoProvider`, [UInt8]/Span<UInt8> currency, one TLSError.
        // Dual-build: on host the X.509 strategy bridges (TLSCore/DTLSCore) fill the
        // engine seams; under Embedded the facade uses the `P2PCoreDER` raw-public-key
        // strategy and never imports the host X509/Foundation code.
        .target(
            name: "TLS",
            dependencies: facadeDependencies,
            path: "Sources/TLS",
            exclude: ["CONTEXT.md"],
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "TLSCoreTests",
            dependencies: [
                "TLS",
                "TLSCore",
                "TLSRecord",
                "TLSCryptoCore",
                "TLSCryptoProvider",
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
