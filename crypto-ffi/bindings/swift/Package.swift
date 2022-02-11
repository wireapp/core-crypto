// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "CoreCrypto",
    platforms: [.iOS(.v13)],
    products: [
        .library(
            name: "CoreCrypto",
            targets: ["CoreCrypto"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "CoreCrypto",
            path: "out/CoreCrypto.xcframework"
        ),
        .testTarget(
            name: "CoreCryptoTests",
            dependencies: ["CoreCrypto"]
        ),
    ]
)
