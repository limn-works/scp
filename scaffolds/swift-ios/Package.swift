// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "SCPiOSApp",
    platforms: [.iOS(.v17)],
    dependencies: [
        .package(path: "../../bindings/swift"),
    ],
    targets: [
        .executableTarget(
            name: "SCPiOSApp",
            dependencies: [.product(name: "SCP", package: "SCP")],
            path: "Sources"
        ),
    ]
)
