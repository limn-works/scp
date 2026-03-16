# SDK Quickstart

## Overview

SCP provides language SDKs for Rust, Python, TypeScript, Swift, and Kotlin. All five SDKs expose the same protocol operations -- create an identity, create a context, send and receive messages -- through idiomatic language APIs. The Rust core (`crates/scp-core/`) implements all protocol logic; the other four SDKs are thin wrappers over FFI bridges that delegate every operation to Rust.

| Language | Package | FFI Bridge | Import |
|----------|---------|-----------|--------|
| **Rust** | `scp-core` (workspace crate) | N/A (native) | `use scp_core::*;` |
| **Python** | `scp-python` | PyO3 (`crates/scp-ffi/src/`) | `from scp_sdk import Identity, Context` |
| **TypeScript** | `@limn-works/scp-ts` | NAPI (server) / WASM (browser) | `import { Identity, Context } from "@limn-works/scp-ts"` |
| **Swift** | `SCP` (Swift Package) | UniFFI (`crates/scp-ffi/uniffi/`) | `import SCP` |
| **Kotlin** | `works.limn:scp-kt` | UniFFI (`crates/scp-ffi/uniffi/`) | `import works.limn.scp.*` |

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

- Python >= 3.12 (use `python3.12`, not system `python3` which may be Xcode 3.9)
- Rust toolchain (required for building the native extension via `maturin`)
- Pre-built wheels are available for Linux, macOS, and Windows

```bash
python3.12 --version  # >= 3.12
```

### TypeScript

- Bun >= 1.0 or Node >= 22
- The package ships both a NAPI native addon (server) and a WASM module (browser)
- Bridge selection is automatic at import time

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

### Rust

```rust
use std::sync::Arc;
use scp_identity::{DidDht, ScpIdentity};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_platform::traits::KeyType;

// Create platform adapters (use SqliteKeyCustody for production)
let custody = Arc::new(InMemoryKeyCustody::new());
let storage = Arc::new(InMemoryStorage::new());

// Generate an Ed25519 signing keypair
let key_handle = custody.generate_keypair(KeyType::Ed25519).await?;
let public_key = custody.public_key(&key_handle).await?;

// Create an SCP identity with the generated key
let identity = ScpIdentity {
    did: format!("did:dht:z6Mk{}", hex::encode(&public_key.as_bytes()[..16])),
    signing_key: key_handle,
    active_key: None,
    agent_key: None,
};
println!("DID: {}", identity.did);
```

### Python

```python
import asyncio
from scp_sdk import Identity

async def main():
    identity = await Identity.create(custody="platform")
    print(f"DID: {identity.did}")

asyncio.run(main())
```

### TypeScript

```typescript
import { Identity } from "@limn-works/scp-ts";

const identity = await Identity.create({ custody: "platform" });
console.log(`DID: ${identity.did}`);
```

### Swift

```swift
import SCP

let identity = try await Identity.create(custody: "platform")
print("DID: \(identity.did)")
```

### Kotlin

```kotlin
import works.limn.scp.Identity

suspend fun main() {
    val identity = Identity.create(custody = "platform")
    println("DID: ${identity.did}")
}
```

---

## 4. Create a Context

A context is a bounded, encrypted interaction space. All SCP communication happens within contexts. Contexts are governed by parameters that define capabilities (ceiling), lifetime (TTL), and governance rules.

### Rust

```rust
use scp_core::context::{Capability, ContextMode, ContextParams};
use scp_core::context::manager::ContextManager;

let params = ContextParams {
    mode: ContextMode::Encrypted,
    ceiling: vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::MemberInvite,
    ],
    ..ContextParams::default()
};

// ContextManager coordinates context lifecycle.
// Built with crypto, transport, and event-log providers.
let handle = manager
    .create_context("my-context".to_owned(), params, alice.clone())
    .await?;
println!("Context ID: {}", handle.context_id());
```

### Python

```python
from scp_sdk import Capability, Context, CustodyType, MemoryScope

ctx = await Context.create(
    creator=identity,
    ceiling=[Capability.MESSAGES_READ, Capability.MESSAGES_WRITE, Capability.MEMBER_INVITE],
    memory_scope=MemoryScope.FULL,
    governance="single_admin",
    ttl=3600.0,
)
```

### TypeScript

```typescript
const ctx = await Context.create(identity, {
  ceiling: ["messages:read", "messages:write", "member:invite"],
  mode: "Encrypted",
  governance: "single_admin",
});
```

### Swift

```swift
let params = ContextParams(
    ceiling: ["messages:read", "messages:write", "member:invite"],
    governance: .singleAdmin,
    memoryScope: .full,
    ttlSeconds: 3600,
    promotable: false,
    minProtocolVersion: 0
)
let handle = try await contextCreate(identity: identity, params: params)
```

### Kotlin

```kotlin
val paramsJson = buildJsonObject {
    putJsonArray("ceiling") {
        add(JsonPrimitive("messages:read"))
        add(JsonPrimitive("messages:write"))
        add(JsonPrimitive("member:invite"))
    }
    put("governance", "single_admin")
}.toString()

val contextHandle = bridge.context.create(identityHandle, paramsJson)
```

---

## 5. Send and Receive Messages

Messages are MLS-encrypted, signed with the sender's identity, and tagged with provenance metadata. The SDK handles encryption, signing, and envelope construction transparently.

### Rust

```rust
// Send a message via the ContextManager
manager
    .send_message(&handle, &alice, b"Hello from SCP", None)
    .await?;

// Drain events to see what happened
let events = manager.drain_events("my-context").await;
for event in &events {
    println!("Event: {:?}", event);
}
```

### Python

```python
# Send
await ctx.send(b"Hello from SCP", identity=identity)

# Receive
receiver = await ctx.receive()
async for msg in receiver:
    print(f"{msg.sender_did}: {msg.content}")
    break

await ctx.close(identity)
```

### TypeScript

```typescript
// Send
await ctx.send(new TextEncoder().encode("Hello from SCP"));

// Receive
for await (const msg of ctx.receive()) {
  console.log(`${msg.senderDid}: ${msg.content}`);
  break;
}

await ctx.close();
```

### Swift

```swift
// Send
let payload = "Hello from SCP".data(using: .utf8)!
try await contextSend(handle: handle, identity: identity, payload: payload)

// Receive via MessageListener callback
// class MyListener: MessageListener {
//     func onMessage(message: Message) { ... }
//     func onError(error: ScpError) { ... }
//     func onComplete() { ... }
// }
// try await contextSubscribe(handle: handle, listener: MyListener())

try await contextClose(handle: handle, identity: identity)
```

### Kotlin

```kotlin
// Send
bridge.context.send(contextHandle, "Hello from SCP".toByteArray())

// Receive via Flow
val subscription = bridge.context.subscribe(contextHandle)
subscription.take(1).collect { messageJson ->
    println("Received: $messageJson")
}

bridge.context.close(contextHandle)
```

---

## 6. Error Handling

All SDKs provide structured errors with machine-readable error codes. Error codes follow the `SCP-<PREFIX>-<NUMBER>` convention defined in `.docs/standards/sdk-common.md`.

### Rust

```rust
use scp_core::error::ScpError;

match ctx.send(payload).await {
    Ok(_) => println!("sent"),
    Err(ScpError::Context(e)) => eprintln!("[{}] {}", e.code(), e),
    Err(e) => eprintln!("unexpected: {e}"),
}
```

### Python

```python
from scp_sdk import ScpError, ContextError

try:
    await ctx.send(b"data")
except ContextError as e:
    print(f"[{e.code}] {e}")
```

### TypeScript

```typescript
import { ScpError, ContextError } from "@limn-works/scp-ts";

try {
  await ctx.send(payload);
} catch (e) {
  if (e instanceof ContextError) {
    console.error(`[${e.code}] ${e.message}`);
  }
}
```

### Swift

```swift
do {
    try await ctx.send(Data("data".utf8))
} catch ScpError.context(let message, let code) {
    print("[\(code)] \(message)")
}
```

### Kotlin

```kotlin
try {
    ctx.send(payload)
} catch (e: ContextException) {
    println("[${e.code}] ${e.message}")
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

Each SDK ships runnable examples in its `examples/` directory:

| Example | Python | TypeScript | Swift | Kotlin |
|---------|--------|-----------|-------|--------|
| Basic messaging | `basic_messaging.py` | `basic-messaging.ts` | `BasicMessaging.swift` | `BasicMessaging.kt` |
| Tool invocation | `tool_invocation.py` | `tool-invocation.ts` | `ToolInvocation.swift` | `ToolInvocation.kt` |
| MCP integration | `mcp_integration.py` | `mcp-integration.ts` | `McpIntegration.swift` | `McpIntegration.kt` |
| Multi-agent coordination | `multi_agent.py` | `multi-agent.ts` | `MultiAgent.swift` | `MultiAgent.kt` |

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
