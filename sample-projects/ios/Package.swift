// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "MyLibrary",
    products: [
        .library(
            name: "MyLibrary",
            targets: ["MyLibrary", "CoreCrypto"]),
    ],
    dependencies: [
    ],
    targets: [
        .binaryTarget(name: "CoreCrypto", path: "CoreCrypto.xcframework"),
        .target(
            name: "MyLibrary",
            dependencies: ["CoreCrypto"]),
        .testTarget(
            name: "MyLibraryTests",
            dependencies: ["MyLibrary"]),
    ]
)
