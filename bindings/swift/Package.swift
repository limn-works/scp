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
                // Swift 6.2's default language mode enables strict concurrency
                // checking that produces errors in UniFFI-generated code (the
                // `sending` parameter pattern in uniffiTraitInterfaceCallAsync).
                // Use Swift 5 language mode to downgrade these to warnings until
                // UniFFI updates its Swift codegen for Swift 6 compatibility.
                .swiftLanguageMode(.v5),
            ]
        ),
        .testTarget(
            name: "SCPTests",
            dependencies: ["SCP"],
            path: "Tests/SCPTests",
            swiftSettings: [
                // Match the SCP target's language mode for consistency.
                .swiftLanguageMode(.v5),
            ]
        ),
    ]
)
