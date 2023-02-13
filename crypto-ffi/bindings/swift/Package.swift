// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "CoreCrypto",
    platforms: [.iOS(.v12)],
    products: [
        .library(
            name: "CoreCrypto",
            targets: ["CoreCrypto", "CoreCryptoSwift", "LibCoreCrypto"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "CoreCrypto",
            dependencies: ["CoreCryptoSwift"]
        ),
        .binaryTarget(
            name: "LibCoreCrypto",
            url: "https://github.com/wireapp/core-crypto/releases/download/#VERSION/LibCoreCrypto.xcframework.zip",
            checksum: "#CHECKSUM"
        ),
        .target(
            name: "CoreCryptoSwift",
            dependencies: ["LibCoreCrypto"]
        ),
    ]
)
