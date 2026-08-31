> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

# Swift SDK Scaffold

Build blueprint for the SCP Swift SDK: package structure, UniFFI bridge patterns, XCFramework build, and type definitions. See `.docs/standards/swift.md` for coding standards (Swift conventions, safety rules, concurrency, testing, CI).

## UniFFI Bridge

UniFFI generates Swift bindings from the same UDL file used for Kotlin (`crates/scp-ffi/uniffi/src/scp.udl`).

UniFFI generates:
- `ScpBindings.swift` — Swift classes, enums, and functions wrapping the Rust FFI
- XCFramework-compatible headers and module maps

### Async bridging

UniFFI supports Swift concurrency via `CheckedContinuation`:

```swift
public actor Context {
    private let handle: ContextHandle

    public func send(_ payload: Data) async throws {
        try await withCheckedThrowingContinuation { continuation in
            handle.send(payload) { error in
                if let error { continuation.resume(throwing: error.toScpError()) }
                else { continuation.resume() }
            }
        }
    }

    public var messages: AsyncStream<Message> {
        AsyncStream { continuation in
            handle.subscribe { envelope in
                continuation.yield(envelope.toMessage())
            } onComplete: {
                continuation.finish()
            }
        }
    }
}
```

## Package Layout

```
bindings/swift/
  Package.swift                   # SPM package definition
  Sources/
    SCP/
      Identity.swift              # Identity class, DIDDocument
      Context.swift               # Context actor, Membership
      Tools.swift                 # ToolDefinition, TestVector structs
      Trust.swift                 # evaluateTrust(), TrustEvaluation
      EventLog.swift              # EventLog class, Event, Proof, Checkpoint
      Errors.swift                # Error hierarchy (ScpError enum)
      Transport.swift             # TransportConfig, relay connection
      Types.swift                 # Shared types: Message, Provenance, Capability
      Ucan.swift                  # UCAN validate(), mint(), revoke()
      Mcp.swift                   # serveMcp(), McpClient
      Internal/
        ScpBindings.swift         # UniFFI-generated bindings (auto-generated)
  Tests/
    SCPTests/
      IdentityTests.swift
      ContextTests.swift
      ToolsTests.swift
      UcanTests.swift
      TransportTests.swift
      EventLogTests.swift
      McpTests.swift
      Conformance/
        ConformanceTests.swift
```

## Package.swift

```swift
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
            path: "Sources/SCP"
        ),
        .testTarget(
            name: "SCPTests",
            dependencies: ["SCP"],
            path: "Tests/SCPTests"
        ),
    ]
)
```

## XCFramework Build

The Rust shared library is compiled into an XCFramework for SPM distribution:

```bash
# Build Rust for all Apple targets
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
cargo build --release --target x86_64-apple-ios
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

# Create fat library for iOS simulator
lipo -create \
  target/aarch64-apple-ios-sim/release/libscp_ffi.a \
  target/x86_64-apple-ios/release/libscp_ffi.a \
  -output libscp_ffi_sim.a

# Create fat library for macOS
lipo -create \
  target/aarch64-apple-darwin/release/libscp_ffi.a \
  target/x86_64-apple-darwin/release/libscp_ffi.a \
  -output libscp_ffi_macos.a

# Create XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libscp_ffi.a -headers include/ \
  -library libscp_ffi_sim.a -headers include/ \
  -library libscp_ffi_macos.a -headers include/ \
  -output ScpFFI.xcframework
```

## SDK Type Definitions

### Identity

```swift
public struct Identity: Sendable {
    public let did: String
    public let custodyType: String

    private let handle: IdentityHandle

    public static func create(custody: String) async throws -> Identity {
        let handle = try await ScpBindings.identityCreate(custody: custody)
        return Identity(did: handle.did(), custodyType: handle.custodyType(), handle: handle)
    }

    public static func load(did: String) async throws -> Identity { ... }

    public func rotateKey() async throws -> Identity { ... }
}
```

`create` takes the custody string as a required argument and offers no default, because
key custody is a security-relevant choice and the agent-first API design tenet in
CLAUDE.md forbids an SDK picking one on a caller's behalf. §3.2.2 of the identity spec,
the custody vocabulary, states the two values this string carries: `"encrypted_file"`
selects the on-disk key store SCP implements, and `"os_keystore"` selects Keychain
through the platform key-custody callback the SDK consumer supplies. `"os_keystore"`
states which store holds the key and states nothing about hardware isolation, because
the Secure Enclave supports only P-256 while SCP signs Ed25519, so Keychain holds SCP's
keys in software (`bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:217`–`:221`).
A shipped build answers every other string with a typed error, and answers the
test-harness string `"in_memory"` with `SCP-IDENT-1008`. The words `platform`,
`software`, `file`, and `hardware` name no custody value.

### Error types

Swift errors as an enum with associated values:

```swift
public enum ScpError: Error, Sendable {
    case identity(message: String, code: String)
    case context(message: String, code: String)
    case permission(message: String, code: String)
    case crypto(message: String, code: String)
    case transport(message: String, code: String)
    case tool(message: String, code: String)
    case validation(message: String, code: String)
}

extension ScpError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .identity(let message, _): message
        case .context(let message, _): message
        // ...
        }
    }
}
```

### Value types

```swift
public struct Message: Sendable {
    public let senderDid: String
    public let content: Data
    public let timestamp: TimeInterval
    public let sequence: Int64
    public let contextId: String
    public let provenance: Provenance?
}

public struct ToolDefinition: Sendable {
    public let name: String
    public let description: String
    public let inputSchema: String    // JSON string
    public let outputSchema: String   // JSON string
    public let operatorDid: String
    public let testVectors: [TestVector]?
    public let implementationHash: Data?
}
```

## Documentation

Swift API reference is generated with DocC. Because DocC requires a resolved SPM package (which depends on the `ScpFFI.xcframework` binary target), documentation generation runs as a post-step of the `swift-xcframework` job in `.github/workflows/build-matrix.yml`, not in the standalone `docs.yml` workflow.

```bash
# Generate DocC (requires ScpFFI.xcframework to be present)
cd bindings/swift
swift package generate-documentation --target SCP --output-path docs
```

The CI step uploads the output as a `docs-swift` artifact, which the `publish-docs` job in `docs.yml` collects by pattern when publishing to GitHub Pages on release tags.

## SPM Distribution

Published as `SCP` Swift Package via GitHub releases with XCFramework binary target.

```swift
// Consumer usage in Package.swift
dependencies: [
    .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
]
```
