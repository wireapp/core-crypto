// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "CoreCrypto",
    platforms: [.iOS(.v13)],
    products: [
        .library(
            name: "CoreCrypto",
            targets: ["CoreCrypto", "CoreCryptoFramework"]
        )
    ],
    targets: [
        .target(
            name: "CoreCrypto",
            dependencies: ["CoreCryptoFramework"],
            cSettings: [.headerSearchPath("include")]
        ),
        .binaryTarget(
            name: "CoreCryptoFramework",
            path: "./out/CoreCrypto.xcframework"
        ),
        .testTarget(
            name: "CoreCryptoTests",
            dependencies: ["CoreCrypto"]
        )
    ]
)
