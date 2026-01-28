// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "swift-tls",
    platforms: [
        .macOS(.v15), .iOS(.v18), .tvOS(.v18),
        .watchOS(.v11), .visionOS(.v2),
    ],
    products: [
        .library(name: "TLSCore", targets: ["TLSCore"]),
        .library(name: "TLSRecord", targets: ["TLSRecord"]),
        .library(name: "DTLSCore", targets: ["DTLSCore"]),
        .library(name: "DTLSRecord", targets: ["DTLSRecord"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.1"),
    ],
    targets: [
        .target(
            name: "TLSCore",
            dependencies: [
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
