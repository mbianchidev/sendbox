// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "sendbox",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .executable(name: "sendbox", targets: ["sendbox"]),
        .library(name: "SendBoxKit", targets: ["SendBoxKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", from: "0.1.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-testing.git", from: "0.12.0"),
    ],
    targets: [
        .executableTarget(
            name: "sendbox",
            dependencies: [
                "SendBoxKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .target(
            name: "SendBoxKit",
            dependencies: [
                .product(
                    name: "Containerization",
                    package: "containerization",
                    condition: .when(platforms: [.macOS])
                ),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Yams", package: "Yams"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .testTarget(
            name: "SendBoxKitTests",
            dependencies: [
                "SendBoxKit",
                .product(name: "Testing", package: "swift-testing"),
            ],
            exclude: ["Fixtures"]
        ),
    ]
)
