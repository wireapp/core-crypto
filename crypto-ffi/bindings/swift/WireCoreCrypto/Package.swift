// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "WireCoreCrypto",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "WireCoreCrypto", targets: ["WireCoreCrypto"])
    ],
    dependencies: [
        .package(path: "../WireCoreCryptoUniffi")
    ],
    targets: [
        .target(
            name: "WireCoreCrypto",
            dependencies: ["WireCoreCryptoUniffi"],
            swiftSettings: [
                // compile in Swift 5.x language mode, which still allows non-@Sendable Task closures
                // https://github.com/mozilla/uniffi-rs/issues/2448
                .swiftLanguageMode(.v5)
            ]
        ),
        .testTarget(
            name: "WireCoreCryptoTests",
            dependencies: ["WireCoreCrypto"],
            resources: [
                .process(
                    "test-resources/migrating-key-types-to-bytes-test-E4D08634-D1AE-40C8-ADF4-34CCC472AC38.sqlite"
                )
            ],
            swiftSettings: [
                // compile in Swift 5.x language mode, which still allows non-@Sendable Task closures
                // https://github.com/mozilla/uniffi-rs/issues/2448
                .swiftLanguageMode(.v5)
            ]
        ),
    ]
)
