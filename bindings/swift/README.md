# SCP Swift SDK

> `SCP` -- Shared Context Protocol for Swift

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Built on Rust via UniFFI, distributed as XCFramework.

## Install

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
]
```

## Quick Start

```swift
import SCP

// Storage selection is required — there is no default (spec §17.6).
let scp = try SCP(storage: .inMemory)

// Create a cryptographic identity (DID). Supply your own type conforming to
// `KeyCustodyProvider` — see "Key custody" below for what it must implement.
// On a released XCFramework this call throws SCP-IDENT-1059 — read "No shipped
// build creates an identity yet" below before you run it.
let keychain: KeyCustodyProvider = MyKeychainCustody()
let identity = try await scp.identityCreateWithCustody(provider: keychain)
print("DID: \(identity.did())")

// Create an encrypted context
let ctx = try await scp.contextCreate(
    identity: identity,
    params: ContextParams(
        mode: .encrypted,
        ceiling: ["msg:send", "msg:receive"],
        ceilingPolicy: .immutable,
        governance: .singleAdmin,
        memoryScope: .ephemeral,
        ttlSeconds: 3600,
        promotable: false,
        minProtocolVersion: 0,
        maxChainDepth: nil,
        maxNestingDepth: nil,
        sessionCap: nil,
        economicPolicy: nil,
        consequenceRulesJson: nil,
        consequenceConfigJson: nil
    )
)

// Send a message (MLS-encrypted, signed, provenance-tagged)
try await scp.contextSend(
    handle: ctx,
    identity: identity,
    payload: Data("Hello from SCP".utf8),
    spendingUcanJwt: nil
)

try await scp.contextClose(handle: ctx, identity: identity)
```

## Key custody

`identityCreate` takes a custody string, and the UniFFI bridge builds a key
store from one string only: `"in_memory"`, which it compiles under its `testing`
feature. A released XCFramework throws `ScpError.Identity` carrying
`SCP-IDENT-1008` for `"in_memory"`, and it throws `ScpError.Identity` carrying
`SCP-IDENT-1003` for `"platform"` and for `"software"`. No custody string
reaches Keychain or Secure Enclave.

Production key storage runs through
`scp.identityCreateWithCustody(provider:)` instead, which takes a value
conforming to the UniFFI-generated `KeyCustodyProvider` protocol. The private
key material never crosses into the native core, because the core delegates
every cryptographic operation back to the provider's callbacks (ADR-006, the
platform abstraction).

This package ships `AppleKeyCustody`, which stores Ed25519 and X25519 key
material in the Keychain, takes an optional access group and a biometric
policy, and reports `"software"` or `"software_biometric"` from `custodyType`
— the Secure Enclave generates P-256 keys and SCP signs with Ed25519. It
carries the method set `KeyCustodyProvider` declares, but it does not declare
conformance to that protocol: `Sources/SCP/Platform/AppleKeyCustody.swift`
declares `public final class AppleKeyCustody: Sendable` and adds its methods in
a plain `public extension AppleKeyCustody`, so no declaration names the
protocol. Passing it to `identityCreateWithCustody` therefore does not compile
today, and a caller writes their own conforming type until that conformance
lands.

## No shipped build creates an identity yet

`identityCreateWithCustody(provider:)` throws `ScpError.Identity` carrying
`SCP-IDENT-1059` on every released XCFramework. `identityCreate` stops one step
earlier, with the `SCP-IDENT-1008` and `SCP-IDENT-1003` codes described above,
because the bridge rejects every custody string before it reaches the
pre-rotation step. Section 9.7.4.1 of the security model, pre-rotation key
custody, makes every identity commit a pre-rotation commitment when it is
created. That commitment needs a `PreRotationCustody` backend, and the only
implementation is the test-harness `InMemoryPreRotationCustody`, which the
bridge's `testing` feature severs from production, so
`crates/scp-ffi/uniffi/src/bridge.rs` returns the typed error rather than
minting the test double. ADR-062, capability injection and prove-absent dev
backends, records that state as accepted in its §Decision 6 and holds the real
backend out of its own scope. The Quick Start above therefore runs against a
framework built with the `testing` feature.

Two separate gaps produce those codes, and closing one does not close the
other. `SCP-IDENT-1003` and `SCP-IDENT-1008` say that the custody string you
passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
pre-rotation custody backend exists for any create path to use. A wired
platform provider clears the first gap; a real pre-rotation backend clears the
second.

## Platform Support

- iOS >= 17
- macOS >= 14

## API Reference

Generated from source via DocC. Build locally:

```bash
swift package generate-documentation --target SCP
```

Published API docs are generated on every release by CI.

## Examples

See [`examples/`](./examples/) for runnable code:

| File | Description |
|------|-------------|
| `BasicMessaging.swift` | Create identity, context, send/receive messages |
| `OutletInvocation.swift` | Register and invoke a outlet with test vectors |
| `McpIntegration.swift` | Expose SCP outlets via MCP JSON-RPC server |
| `MultiAgent.swift` | Coordinate multiple agents in a shared context |

## Error Handling

All errors are cases of the `ScpError` enum with associated `message` and `code` values:

```swift
do {
    try await ctx.send(Data("data".utf8))
} catch ScpError.context(let message, let code) {
    print("[\(code)] \(message)")
}
```

## Source

- Scaffold: `.docs/scaffold/swift.md`
- Standards: `.docs/standards/swift.md`
- API sketch: `.docs/sketch.md`
