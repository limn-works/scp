// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "SCPmacOSApp",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../../bindings/swift"),
    ],
    targets: [
        .executableTarget(
            name: "SCPmacOSApp",
            dependencies: [.product(name: "SCP", package: "SCP")],
            path: "Sources"
        ),
    ]
)
