// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "SCP",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "SCP", targets: ["SCP"]),
    ],
    targets: [
        .binaryTarget(
            name: "ScpFFI",
            path: "ScpFFI.xcframework"
        ),
        .target(
            name: "SCP",
            dependencies: ["ScpFFI"],
            path: "Sources/SCP",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "SCPTests",
            dependencies: ["SCP"],
            path: "Tests/SCPTests"
        ),
    ]
)
