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
        .library(name: "TLSWireCore", targets: ["TLSWireCore"]),
        .library(name: "DTLSWireCore", targets: ["DTLSWireCore"]),
        .library(name: "TLSCore", targets: ["TLSCore"]),
        .library(name: "TLSRecord", targets: ["TLSRecord"]),
        .library(name: "DTLSCore", targets: ["DTLSCore"]),
        .library(name: "DTLSRecord", targets: ["DTLSRecord"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.1"),
        .package(path: "../swift-p2p-core"),
    ],
    targets: [
        // ---- Embedded-clean wire codec (dual-build: host + Embedded) ----
        .target(
            name: "TLSWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/TLSWireCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean DTLS wire codec (dual-build: host + Embedded) ----
        .target(
            name: "DTLSWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                "TLSWireCore",
            ],
            path: "Sources/DTLSWireCore",
            swiftSettings: coreSettings
        ),
        // ---- Foundation adapter: keeps the existing Data-based public API ----
        .target(
            name: "TLSCore",
            dependencies: [
                "TLSWireCore",
                .product(name: "P2PCoreFoundation", package: "swift-p2p-core"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Sources/TLSCore"
        ),
        .target(
            name: "TLSRecord",
            dependencies: [
                "TLSCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/TLSRecord"
        ),
        .target(
            name: "DTLSCore",
            dependencies: [
                "TLSCore",
                "DTLSWireCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            path: "Sources/DTLSCore"
        ),
        .target(
            name: "DTLSRecord",
            dependencies: [
                "DTLSCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/DTLSRecord"
        ),
        .testTarget(
            name: "TLSCoreTests",
            dependencies: ["TLSCore", "TLSRecord"],
            path: "Tests/TLSCoreTests"
        ),
        .testTarget(
            name: "TLSRecordTests",
            dependencies: ["TLSRecord", "TLSCore"],
            path: "Tests/TLSRecordTests"
        ),
        .testTarget(
            name: "DTLSCoreTests",
            dependencies: ["DTLSCore", "TLSCore"],
            path: "Tests/DTLSCoreTests"
        ),
        .testTarget(
            name: "DTLSRecordTests",
            dependencies: ["DTLSRecord", "DTLSCore"],
            path: "Tests/DTLSRecordTests"
        ),
    ]
)
