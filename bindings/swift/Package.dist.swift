// swift-tools-version: 6.2
// AUTO-GENERATED distribution manifest for the limn-works/scp-swift mirror.
//
// This template is materialized by the release pipeline (.github/workflows/
// release.yml, job `publish-spm`): the placeholders below are substituted with
// the published XCFramework's GitHub Release URL and its SHA-256 checksum, and
// the result is committed to https://github.com/limn-works/scp-swift as the
// root Package.swift consumed by SwiftPM.
//
// SwiftPM requires a root manifest plus SemVer git tags, neither of which the
// monorepo can provide (the Swift sources live under bindings/swift/ and the
// repo is tagged per-component as scp-<crate>@<version>). The mirror exists to
// satisfy those two requirements while the binary itself stays a release
// artifact of this repo. Do not hand-edit the mirror — every release
// regenerates it.
import PackageDescription

let package = Package(
    name: "SCP",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "SCP", targets: ["SCP"])
    ],
    targets: [
        .binaryTarget(
            name: "ScpFFI",
            url: "__SCP_XCFRAMEWORK_URL__",
            checksum: "__SCP_XCFRAMEWORK_CHECKSUM__"
        ),
        .target(
            name: "SCP",
            dependencies: ["ScpFFI"],
            path: "Sources/SCP",
            swiftSettings: [
                // Match the monorepo manifest: Swift 6.2's default language mode
                // surfaces strict-concurrency errors in UniFFI-generated code.
                .swiftLanguageMode(.v5)
            ],
            linkerSettings: [
                // The `whoami` crate (transitive via scp-node) calls
                // SCDynamicStoreCopyComputerName on macOS/iOS.
                .linkedFramework("SystemConfiguration")
            ]
        )
    ]
)
