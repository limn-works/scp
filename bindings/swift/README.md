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
// Supply your own type conforming to KeyCustodyProvider; this package
// ships none that conforms — see "Key custody" below.
let keychain: KeyCustodyProvider = YourKeychainCustody()
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

`identityCreate` takes a `CustodyType` and carries no default, so a caller names
the key store and this SDK names none for them. Section 3.2.2 of the identity
spec, "The Custody Vocabulary", states the two values `CustodyType` carries.
`.encryptedFile` (`"encrypted_file"`) selects the on-disk key store SCP
implements, which derives the file key with Argon2id and encrypts
`$HOME/.scp/keys.bin` with AES-256-GCM. `.osKeystore` (`"os_keystore"`) selects
the operating system's own key store, which SCP reaches through the platform
key-custody callback you supply. Every other string throws
`ScpError.Validation` carrying `SCP-VALID-7005`, and that includes
`"platform"`, `"software"`, `"file"`, `"platform_managed"`, and `"hardware"`.

`scp.identityCreate(custody: .osKeystore)` throws `ScpError.Identity` carrying
`SCP-IDENT-1003`, because that call supplies no provider and the bridge falls
back to neither the encrypted key file nor an in-memory store. Reaching Keychain
runs through `scp.identityCreateWithCustody(provider:)` instead, which takes a
value conforming to the UniFFI-generated `KeyCustodyProvider` protocol. The
private key material never crosses into the native core, because the core
delegates every cryptographic operation back to the provider's callbacks
(ADR-006, the platform abstraction).

An XCFramework built with the bridge's `testing` cargo feature additionally
accepts the raw string `"in_memory"`, which reaches the test-only in-memory key
store. No `CustodyType` case spells it, a test that needs it passes the raw
string to the UniFFI `Scp` object, and a released XCFramework throws
`ScpError.Identity` carrying `SCP-IDENT-1008`.

This package ships `AppleKeyCustody`, which stores Ed25519 and X25519 key
material in the Keychain and reports `"software"` or `"software_biometric"`
from `custodyType` — the Secure Enclave generates P-256 keys and SCP signs with
Ed25519. You cannot pass it to `identityCreateWithCustody`, and adding
`: KeyCustodyProvider` to it does not make you able to.
`Sources/SCP/Platform/AppleKeyCustody.swift` declares `public final class
AppleKeyCustody: Sendable`, and ten of the eleven methods it defines differ
from the protocol's by argument label, by return type, or by both: the protocol
declares `getPublicKey(keyId:)` where the class defines `publicKey(_:)`, and it
declares `destroyKey(keyId:)` returning `Void` where the class defines
`destroyKey(_:)` returning `DestructionAttestation`. Only
`generateKeypair(keyType:)` matches. Write your own conforming type until an
adapter lands.

## What a DID document publishes about custody

`scp.identityPublishedCustody(did:)` returns what a stranger reading that DID
document learns about custody, which section 3.2.2 states is whether the key can
leave its store and which factor unlocks it: `"non-extractable-biometric"`,
`"non-extractable-pin"`, or `"extractable-passphrase"`. It returns `nil` when
the backend holding the `#active` key reports a pair the published vocabulary
states no value for.

The bridge derives the value from the running backend, so a participant cannot
publish a custody they do not run. `KeyCustodyProvider.keyIsExtractable` and
`KeyCustodyProvider.unlockFactor` answer the two questions for an injected
provider.

`AppleKeyCustody` answers both questions with its own method signatures, which
`identityCreateWithCustody` cannot reach until an adapter lands (see "Key
custody" above). It answers `true` to the first for every key it holds, because
`exportSigningKeyBytes` reads the raw private-key bytes out of the Keychain item
and returns a copy of them, and the Secure Enclave — which holds a key
non-extractably — generates P-256 keys only. It answers `"biometric"` to the
second under `BiometricPolicy.required`. Under `BiometricPolicy.none` it answers
`"caller_supplied_key"`, which names no factor it verified: the item then
carries `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, and no artifact
states which factor that protection class means — the device passcode
(`"passphrase"`) or nothing at all (`"unprotected"`). The bridge publishes
`extractable-passphrase` for the first answer and nothing for the second, so
the adapter reports neither while the question is open, and the bridge publishes
nothing for the pair it does report.

## No shipped build creates an identity yet

`identityCreateWithCustody(provider:)` throws `ScpError.Identity` carrying
`SCP-IDENT-1059` on every released XCFramework, and
`identityCreate(custody: .encryptedFile)` throws it too once
`SCP_KEY_PASSPHRASE` is set. Section 9.7.4.1 of the
security model, pre-rotation key custody, makes every identity commit a
pre-rotation commitment when it is created. That commitment needs a
`PreRotationCustody` backend, and the only implementation is the test-harness
`InMemoryPreRotationCustody`, which the
bridge's `testing` feature severs from production, so
`crates/scp-ffi/uniffi/src/bridge.rs` returns the typed error rather than
minting the test double. ADR-062, capability injection and prove-absent dev
backends, records that state as accepted in its §Decision 6 and holds the real
backend out of its own scope. The Quick Start above therefore runs against a
framework built with the `testing` feature.

Two separate gaps produce those codes, and closing one does not close the
other. `SCP-IDENT-1003`, `SCP-IDENT-1008`, and `SCP-VALID-7005` say that the
custody value you passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
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
