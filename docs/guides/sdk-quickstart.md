# SDK Quickstart

## Overview

SCP provides language SDKs for Rust, Python, TypeScript, Swift, and Kotlin. The Rust core (`crates/scp-core/`) implements all protocol logic; the Python, TypeScript, Swift and Kotlin SDKs are thin wrappers over FFI bridges that delegate every operation to Rust, each through one `SCP` instance whose methods are the whole public API. The code in sections 3 to 6 covers those four SDKs. A Rust program depends on the workspace crates directly.

| Language | Package | FFI Bridge | Import |
|----------|---------|-----------|--------|
| **Rust** | `scp-core` (workspace crate) | N/A (native) | `use scp_core::*;` |
| **Python** | `scp-python` | PyO3 (`crates/scp-ffi/src/`) | `from scp_sdk import SCP, CustodyType` |
| **TypeScript** | `@limn-works/scp-ts` | NAPI (server, in-process); browser = in-tab wasm client (`@limn-works/scp-ts-wasm`, ADR-057) | `import { SCP } from "@limn-works/scp-ts"` |
| **Swift** | `SCP` (Swift Package) | UniFFI (`crates/scp-ffi/uniffi/`) | `import SCP` |
| **Kotlin** | `works.limn:scp-kt` | UniFFI (`crates/scp-ffi/uniffi/`) | `import works.limn.scp.SCP` |

**Contents:**
1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Create an Identity](#3-create-an-identity)
4. [Create a Context](#4-create-a-context)
5. [Send and Receive Messages](#5-send-and-receive-messages)
6. [Error Handling](#6-error-handling)
7. [Where to Go Next](#7-where-to-go-next)

---

## 1. Prerequisites

### Rust

- Rust toolchain (stable, edition 2021+)
- The SCP workspace is managed via [mise](https://mise.jdx.dev/). Run `eval "$(mise env)"` before building.

```bash
# Verify toolchain
rustc --version  # >= 1.75
cargo --version
```

### Python

- CPython 3.10 or later, the `requires-python` floor in `bindings/python/pyproject.toml` (in this repository use `python3.12`, which mise installs, not system `python3`, which may be Xcode 3.9)
- Pre-built wheels cover CPython 3.10-3.13 on Linux x86_64 and aarch64 with glibc 2.28 or newer (manylinux_2_28), macOS 11 or newer (universal2), and Windows x86_64; installing one needs no Rust toolchain
- A build from source, both when pip falls back to the source distribution because no wheel matches and when you run `maturin develop` in `bindings/python`, needs a Rust toolchain, a C compiler, and, on Linux and Windows, a full perl (plus make on Linux) for the OpenSSL the build compiles; `bindings/python/README.md` §Requirements has the details

```bash
python3.12 --version
```

### TypeScript

- Bun >= 1.0 or Node >= 22
- The package ships a NAPI native addon for server runtimes (Bun/Node), running the protocol engine in-process
- In the browser the full protocol runs in-tab via the sibling wasm tier `@limn-works/scp-ts-wasm`, keys on-device (ADR-057); a remote custodial thin client to a server-side `scp-node` is an optional mode, not the default

```bash
bun --version   # >= 1.0
# or
node --version  # >= 22
```

### Swift

- Swift >= 6.2, Xcode 16+
- macOS >= 14 or iOS >= 17
- The SDK is distributed as a Swift Package wrapping a UniFFI-generated XCFramework

```bash
swift --version  # >= 6.2
```

### Kotlin

- Kotlin >= 2.0, JDK >= 11
- Gradle 8.x
- `kotlinx-coroutines-core` for suspend function support
- All tools managed via mise: `eval "$(mise env)"` sets `JAVA_HOME`

```bash
eval "$(mise env)"
java -version    # >= 11
kotlin -version  # >= 2.0
```

---

## 2. Installation

### Rust

Add workspace crates to your `Cargo.toml`:

```toml
[dependencies]
scp-core = { path = "crates/scp-core" }
scp-identity = { path = "crates/scp-identity" }
scp-platform = { path = "crates/scp-platform" }
scp-transport = { path = "crates/scp-transport" }
```

For out-of-tree projects, use published versions from crates.io once available.

### Python

```bash
pip install scp-python
```

For development against the local workspace:

```bash
cd bindings/python
pip install maturin
maturin develop --release
```

### TypeScript

```bash
bun add @limn-works/scp-ts
# or
npm install @limn-works/scp-ts
```

### Swift

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
]
```

### Kotlin

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("works.limn:scp-kt:0.1.0")
}
```

---

## 3. Create an Identity

Every SCP participant starts by creating a cryptographic identity -- a DID (Decentralized Identifier) backed by Ed25519 keys. The identity is the root of trust for all protocol operations.

Every SDK takes the custody choice as a required argument. Python's key store value is `CustodyType.ENCRYPTED_FILE`; a build without the bridge's `testing` feature has no pre-rotation custody backend and raises `SCP-IDENT-1059` for it. TypeScript's `CustodyType` carries `"encrypted_file"` and `"os_keystore"` and no other value (`03-identity.md` §3.2.2), and a shipped addon answers `"encrypted_file"` with `SCP-IDENT-1059` as Python's build does. The Swift and Kotlin SDKs ship no key store that `identityCreate` reaches: each one's only custody value, `in_memory`, works only in a build compiled with the `testing` feature, and a shipped build rejects it with `SCP-IDENT-1008`. In TypeScript, Swift and Kotlin a production caller implements `KeyCustodyProvider` over its own key store and passes it to `identityCreateWithCustody`.

### Python

```python
import asyncio
from scp_sdk import SCP, CustodyType

async def main():
    async with SCP({"type": "sqlite", "path": "./scp-data", "passphrase": "change me"}) as scp:
        # CustodyType.ENCRYPTED_FILE keeps the keys in $HOME/.scp/keys.bin, encrypted
        # under the SCP_KEY_PASSPHRASE environment variable. A build without the
        # bridge's testing feature has no pre-rotation custody backend and raises
        # SCP-IDENT-1059.
        identity = await scp.identity_create(CustodyType.ENCRYPTED_FILE)
        print(f"DID: {identity.did}")

asyncio.run(main())
```

### TypeScript

```typescript
import { type KeyCustodyProvider, SCP } from "@limn-works/scp-ts";

declare const provider: KeyCustodyProvider; // your key store

const scp = new SCP({ storage: { type: "sqlite", path: "./scp-data", passphrase: "change me" } });
const identity = await scp.identityCreateWithCustody(provider);
console.log(`DID: ${identity.did}`);
```

### Swift

```swift
import SCP

let provider: KeyCustodyProvider = MyKeyStore()  // your key store
let scp = try SCP.withStorage(sqliteDir: storageDir, passphrase: "change me")
let identity = try await scp.identityCreateWithCustody(provider: provider)
print("DID: \(identity.did())")
```

### Kotlin

```kotlin
import uniffi.scp.KeyCustodyProvider
import works.limn.scp.SCP

suspend fun createIdentity(provider: KeyCustodyProvider, storageDir: java.io.File) {
    val scp = SCP.withSqlite(storageDir, "change me")
    val identity = scp.identityCreateWithCustody(provider)
    println("DID: ${identity.did()}")
}
```

---

## 4. Create a Context

A context is a bounded, encrypted interaction space. All SCP communication happens within contexts. Contexts are governed by parameters that define capabilities (ceiling), lifetime (TTL), and governance rules.

### Python

```python
from scp_sdk import Capability, MemoryScope

ctx = await scp.context_create(
    identity.did,
    {
        "ceiling": [
            Capability.MESSAGES_READ.value,
            Capability.MESSAGES_WRITE.value,
            Capability.MEMBER_INVITE.value,
        ],
        "memory_scope": MemoryScope.FULL.value,
        "governance": "single_admin",
    },
)
print(f"Context ID: {ctx.context_id}")
```

### TypeScript

```typescript
import type { ContextParams } from "@limn-works/scp-ts";

const params: ContextParams = {
  ceiling: ["messages:read", "messages:write", "member:invite"],
  mode: "Encrypted",
  governance: "single_admin",
};
const ctx = await scp.contextCreate(identity, JSON.stringify(params));
console.log(`Context ID: ${ctx.contextId}`);
```

### Swift

```swift
let params = ContextParams(
    mode: .encrypted,
    ceiling: ["messages:read", "messages:write", "member:invite"],
    ceilingPolicy: .immutable,
    governance: .singleAdmin,
    memoryScope: .full,
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
let handle = try await scp.contextCreate(identity: identity, params: params)
print("Context ID: \(handle.contextId())")
```

### Kotlin

```kotlin
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope

val params = ContextParams(
    mode = ContextMode.ENCRYPTED,
    ceiling = listOf("messages:read", "messages:write", "member:invite"),
    ceilingPolicy = CeilingPolicy.IMMUTABLE,
    governance = GovernanceModel.SINGLE_ADMIN,
    memoryScope = MemoryScope.FULL,
    ttlSeconds = 3600uL,
    promotable = false,
    minProtocolVersion = 0.toUShort(),
    maxChainDepth = null,
    maxNestingDepth = null,
    sessionCap = null,
    economicPolicy = null,
    consequenceRulesJson = null,
    consequenceConfigJson = null,
)
val handle = scp.contextCreate(identity, params)
println("Context ID: ${handle.contextId()}")
```

---

## 5. Send and Receive Messages

Messages are MLS-encrypted, signed with the sender's identity, and tagged with provenance metadata. The SDK handles encryption, signing, and envelope construction transparently.

A message reaches another member's node over a relay. Each node attaches the relay with `configure_relay_transport` (`configureRelayTransport` in the other SDKs) before it creates or joins its first context: that context starts the node's context supervisor, which binds the transport the node has then, and a later call attaches nothing. A send to a member whose routing announcement has not yet arrived fails with `SCP-CTX-2095` and is rolled back, so it is safe to retry. The `messaging` example for each SDK runs the full flow on two nodes: relay, create, invite, join, send, receive.

The Python SDK does not yet subscribe a context to the relay, so a Python node receives nothing its peer sends, and its sends to a remote member keep failing with `SCP-CTX-2095` (#2856).

### Python

```python
# Before the first context_create or context_join_from_welcome on this node:
await scp.configure_relay_transport("wss://relay.example.com", identity.did)
await scp.transport_connect("wss://relay.example.com")

# Send
await scp.context_send(ctx, identity.did, "Hello from SCP")

# Receive
receiver = await scp.context_receive(ctx)
async for msg in receiver:
    print(msg.sender_did, msg.payload.decode())

await scp.context_leave(ctx, identity.did)
```

### TypeScript

```typescript
// Before the first contextCreate or contextJoinFromWelcome on this node:
await scp.configureRelayTransport("wss://relay.example.com", identity.did);
await scp.transportConnect("wss://relay.example.com");

// Receive: the callback runs once per delivered message.
await scp.contextSubscribe(ctx, identity.did, (message) => {
  console.log(message);
});

// Send
await scp.contextSend(ctx, identity.did, new TextEncoder().encode("Hello from SCP"));

scp.contextCancelSubscription(ctx);
await scp.contextLeave(ctx, identity.did);
```

### Swift

```swift
// Send
let payload = Data("Hello from SCP".utf8)
try await scp.contextSend(handle: handle, identity: identity, payload: payload, spendingUcanJwt: nil)

// Receive via MessageListener callback
// final class MyListener: MessageListener {
//     func onMessage(message: Message) { ... }
//     func onError(error: ScpError) { ... }
//     func onComplete() { ... }
// }
// try await scp.contextSubscribe(handle: handle, listener: MyListener())

try await scp.contextClose(handle: handle, identity: identity)
```

### Kotlin

```kotlin
// Send
scp.contextSend(handle, identity, "Hello from SCP".toByteArray(), spendingUcanJwt = null)

// Receive via MessageListener callback
// class MyListener : MessageListener {
//     override fun onMessage(message: Message) { ... }
//     override fun onError(error: ScpException) { ... }
//     override fun onComplete() { ... }
// }
// scp.contextSubscribe(handle, MyListener())

scp.contextClose(handle, identity)
```

---

## 6. Error Handling

All SDKs provide structured errors with machine-readable error codes. Error codes follow the `SCP-<PREFIX>-<NUMBER>` convention defined in `.docs/standards/sdk-common.md`.

### Python

```python
from scp_sdk import IdentityError

try:
    await scp.identity_create(CustodyType.IN_MEMORY)
except IdentityError as e:
    print(f"[{e.code}] {e}")  # SCP-IDENT-1008 in a shipped build
```

### TypeScript

```typescript
import { IdentityError } from "@limn-works/scp-ts";

try {
  await scp.identityCreate("encrypted_file");
} catch (e) {
  if (e instanceof IdentityError) {
    console.error(`[${e.code}] ${e.message}`); // SCP-IDENT-1059 in a shipped build
  }
}
```

### Swift

```swift
do {
    try await scp.contextSend(handle: handle, identity: identity, payload: Data("data".utf8), spendingUcanJwt: nil)
} catch ScpError.Context(let msg, let code) {
    print("[\(code)] \(msg)")
}
```

### Kotlin

```kotlin
import uniffi.scp.ScpException

try {
    scp.contextSend(handle, identity, payload, spendingUcanJwt = null)
} catch (e: ScpException.Context) {
    println("[${e.code}] ${e.msg}")
}
```

---

## 7. Where to Go Next

### Language-specific scaffolds

Each SDK has a detailed scaffold document in `.docs/scaffold/` that covers the full API surface, project layout, build system, and testing strategy:

| Language | Scaffold | Standards |
|----------|----------|-----------|
| Rust | `.docs/architecture.md` | `.docs/standards/rust.md` |
| Python | `.docs/scaffold/python.md` | `.docs/standards/python.md` |
| TypeScript | `.docs/scaffold/typescript.md` | `.docs/standards/typescript.md` |
| Swift | `.docs/scaffold/swift.md` | `.docs/standards/swift.md` |
| Kotlin | `.docs/scaffold/kotlin.md` | `.docs/standards/kotlin.md` |

### API sketch

The full API surface -- every operation across all subsystems -- is sketched in pseudocode in `.docs/sketch.md`. This is the definitive reference for what operations are available and how they compose.

### Examples

Runnable examples for each SDK sit in `docs/examples/`:

| Example | Python | TypeScript | Swift | Kotlin |
|---------|--------|-----------|-------|--------|
| Identity | `identity.py` | `identity.ts` | `Identity.swift` | `Identity.kt` |
| Context and invite-and-join | `context.py` | `context.ts` | `Context.swift` | `Context.kt` |
| Messaging | `messaging.py` | `messaging.ts` | `Messaging.swift` | `Messaging.kt` |
| Outlets and UCAN | `tools.py` | `tools.ts` | `Tools.swift` | `Tools.kt` |

### Type stubs and IDE support

- **Python:** Ships `py.typed` marker and `_scp_core.pyi` stubs for mypy/pyright.
- **TypeScript:** Ships `.d.ts` type declarations bundled in `dist/`.
- **Swift:** DocC documentation via `swift package generate-documentation`.
- **Kotlin:** KDoc/Dokka documentation via `./gradlew dokkaHtml`.

### Further reading

- [Transport Layer Architecture](architecture.md) -- profiles, adapters, connection model
- [Implementing a Custom TransportAdapter](transport-adapters.md) -- step-by-step MQTT example
- [Storage Backends](storage-backends.md) -- implementing Storage and BlobStorage traits
- [Relay Operations](relay-operations.md) -- building, configuring, and running an SCP relay
- [Conformance Testing](conformance-testing.md) -- using conformance macros to validate implementations
