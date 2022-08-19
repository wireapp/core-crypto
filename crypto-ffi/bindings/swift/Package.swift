// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "CoreCrypto",
    platforms: [.iOS(.v12)],
    products: [
        .library(
            name: "CoreCrypto",
            targets: ["CoreCrypto"]
        ),
    ],
    dependencies: [
        .package(name: "LibCoreCrypto", path: "../libcore-crypto")
    ],
    targets: [
        .target(
            name: "CoreCrypto",
            dependencies: [.productItem(name: "CoreCryptoSwift", package: "LibCoreCrypto", condition: nil)]
        )
    ]
)
