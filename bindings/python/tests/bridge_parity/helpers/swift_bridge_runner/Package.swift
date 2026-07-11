// swift-outlets-version: 6.2
// SPDX-License-Identifier: MIT
//
// Swift parity runner for the ADR-046 bridge parity harness.
//
// A long-lived executable that reads length-prefixed JSON-RPC frames on
// stdin and writes length-prefixed responses on stdout. Dispatches on op
// name into the UniFFI Swift bindings (same JSON-RPC surface as the Bun
// runner and the Kotlin runner — see helpers/node_bridge_runner.ts).
//
// macOS-only: UniFFI Swift bindings ship as an `.xcframework` that
// currently targets Apple platforms. The CI job for this runner is
// pinned to `runs-on: macos-latest`.
//
// Depends on the in-tree SCP package (../../../../../../bindings/swift)
// rather than a published version so the runner always matches the
// bindings built from the same commit.

import PackageDescription

let package = Package(
    name: "SwiftBridgeRunner",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "swift-bridge-runner", targets: ["SwiftBridgeRunner"])
    ],
    dependencies: [
        // Relative path: this file is
        //   bindings/python/tests/bridge_parity/helpers/swift_bridge_runner/Package.swift
        // -> up 6 levels to repo root -> bindings/swift.
        .package(path: "../../../../../../bindings/swift")
    ],
    targets: [
        .executableTarget(
            name: "SwiftBridgeRunner",
            dependencies: [
                .product(name: "SCP", package: "swift")
            ],
            path: "Sources/SwiftBridgeRunner",
            swiftSettings: [
                // Match the SCP target's language mode — avoids Swift 6
                // strict concurrency churn against UniFFI-generated code.
                .swiftLanguageMode(.v5)
            ]
        )
    ]
)
