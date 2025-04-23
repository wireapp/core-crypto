// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: WireCoreCryptoUniffi

import PackageDescription

let package = Package(
    name: "WireCoreCryptoUniffi",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "WireCoreCryptoUniffi",
            targets: ["WireCoreCryptoUniffi"]
        )
    ],
    dependencies: [],
    targets: [
        .binaryTarget(name: "RustFramework", path: "./RustFramework.xcframework"),
        .target(
            name: "WireCoreCryptoUniffi",
            dependencies: [
                .target(name: "RustFramework")
            ],
            swiftSettings: [
                // compile in Swift 5.x language mode, which still allows non-@Sendable Task closures
                .swiftLanguageMode(.v5)
            ]
        ),
    ]
)
