// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "CoreCryptoSwift",
    //platforms: [.iOS(.v13)],
    products: [
        .library(
            name: "CoreCryptoSwift",
            targets: ["CoreCryptoSwift", "CoreCrypto"]
        )
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "CoreCrypto",
            path: "out/CoreCrypto.xcframework"
        ),
        .target(
            name: "CoreCryptoSwift",
            dependencies: ["CoreCrypto"]
        ),
        .testTarget(
            name: "CoreCryptoTests",
            dependencies: ["CoreCryptoSwift"]
        )
    ]
)
