// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibCoreCrypto",
    platforms : [.iOS(.v12)],
    products: [
        .library(
            name: "LibCoreCrypto",
            targets: ["libcore-crypto"]
        ),
        .library(
            name: "CoreCryptoSwift",
            targets: ["CoreCryptoSwift"]
        )
    ],
    dependencies: [],
    targets: [
        .systemLibrary(
            name: "libcore-crypto",
            path: "./lib"
        ),
        .target(
            name: "CoreCryptoSwift",
            dependencies: ["libcore-crypto"]
        )
    ]
)
