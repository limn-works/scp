# SDK Quickstart

SCP ships SDKs for Python, TypeScript, Swift, and Kotlin. All four wrap the same Rust core and expose an identical operational model: create an identity, open a context, send and receive encrypted messages.

This guide walks through the core workflow in all languages side by side. Each section shows the same operation across all SDKs so you can compare idioms and pick the one that fits your stack.

---

## Install

### Python

```bash
pip install scp-sdk
```

Requires Python >= 3.12. Wheels are pre-built for Linux, macOS, and Windows.

### TypeScript

```bash
npm install @scp/sdk
# or
bun add @scp/sdk
```

Works in the browser (WASM) and on the server (Bun >= 1.0, Node >= 22). Bridge selection is automatic at import time.

### Swift

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
]
```

Requires iOS >= 17 or macOS >= 14.

### Kotlin

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.limn:scp-sdk-kotlin:0.1.0")
}
```

Requires Kotlin >= 2.0, JVM >= 11, and `kotlinx-coroutines-core`.

---

## Create an Identity

Every participant in SCP starts with a cryptographic identity -- a DID backed by key material in platform-appropriate custody. No keys are exposed to the user.

### Python

```python
from scp_sdk import Identity

identity = await Identity.create(custody="platform")
print(f"DID: {identity.did}")
```

### TypeScript

```typescript
import { Identity } from "@scp/sdk";

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
import com.limn.scp.Identity

val identity = Identity.create(custody = "platform")
println("DID: ${identity.did}")
```

---

## Create a Context

Contexts are bounded, encrypted, governed spaces. Each context is backed by an MLS group -- membership is enforced by cryptography, not infrastructure. Pass a capability ceiling (the maximum permissions this context can ever grant) and a TTL.

### Python

```python
from scp_sdk import Context

ctx = await Context.create(
    identity=identity,
    params={"ceiling": ["msg:send", "msg:receive"], "ttl": 3600},
)
```

### TypeScript

```typescript
import { Context } from "@scp/sdk";

const ctx = await Context.create(identity, {
  ceiling: ["msg:send", "msg:receive"],
  ttl: 3600,
});
```

### Swift

```swift
let ctx = try await Context.create(
    identity: identity,
    params: ContextParams(
        ceiling: ["msg:send", "msg:receive"],
        ttl: 3600
    )
)
```

### Kotlin

```kotlin
import com.limn.scp.Context

val ctx = Context.create(
    identity = identity,
    params = mapOf(
        "ceiling" to listOf("msg:send", "msg:receive"),
        "ttl" to 3600,
    ),
)
```

---

## Send a Message

Messages are MLS-encrypted, signed with the sender's active signing key, and tagged with provenance metadata. The SDK handles all of this -- you pass bytes.

### Python

```python
await ctx.send(b"Hello from SCP")
```

### TypeScript

```typescript
await ctx.send(new TextEncoder().encode("Hello from SCP"));
```

### Swift

```swift
try await ctx.send(Data("Hello from SCP".utf8))
```

### Kotlin

```kotlin
ctx.send("Hello from SCP".toByteArray())
```

---

## Receive Messages

Each SDK exposes an async iteration primitive native to the language: `async for` in Python, `for await` in TypeScript and Swift, and Kotlin coroutine `Flow`.

### Python

```python
async for msg in ctx.receive():
    print(f"{msg.sender_did}: {msg.content}")
    break
```

### TypeScript

```typescript
for await (const msg of ctx.receive()) {
  console.log(`${msg.senderDid}: ${msg.content}`);
  break;
}
```

### Swift

```swift
for await msg in ctx.messages {
    print("\(msg.senderDid): \(String(data: msg.content, encoding: .utf8)!)")
    break
}
```

### Kotlin

```kotlin
import kotlinx.coroutines.flow.first

val msg = ctx.receiveFlow().first()
println("${msg.senderDid}: ${String(msg.content)}")
```

When you are done with a context, close it to release resources and leave the MLS group:

### Python

```python
await ctx.close()
```

### TypeScript

```typescript
await ctx.close();
```

### Swift

```swift
try await ctx.close()
```

### Kotlin

```kotlin
ctx.close()
```

---

## Error Handling

All SDKs expose a structured error hierarchy rooted in a single base type. Every error carries a machine-readable `code` field for programmatic handling.

### Python

All errors inherit from `ScpError`. Catch specific subclasses for granular handling:

```python
from scp_sdk import ScpError, ContextError

try:
    await ctx.send(b"data")
except ContextError as e:
    print(f"[{e.code}] {e}")
```

### TypeScript

All errors extend `ScpError`. Use `instanceof` for narrowing:

```typescript
import { ScpError, ContextError } from "@scp/sdk";

try {
  await ctx.send(payload);
} catch (e) {
  if (e instanceof ContextError) {
    console.error(`[${e.code}] ${e.message}`);
  }
}
```

### Swift

All errors are cases of the `ScpError` enum with associated `message` and `code` values:

```swift
do {
    try await ctx.send(Data("data".utf8))
} catch ScpError.context(let message, let code) {
    print("[\(code)] \(message)")
}
```

### Kotlin

All exceptions extend `ScpException` with a machine-readable `code` field:

```kotlin
try {
    ctx.send(payload)
} catch (e: ContextException) {
    println("[${e.code}] ${e.message}")
}
```

---

## Full Example

Putting it all together -- the complete workflow in each language.

### Python

```python
import asyncio
from scp_sdk import Identity, Context

async def main():
    identity = await Identity.create(custody="platform")
    print(f"DID: {identity.did}")

    ctx = await Context.create(
        identity=identity,
        params={"ceiling": ["msg:send", "msg:receive"], "ttl": 3600},
    )

    await ctx.send(b"Hello from SCP")

    async for msg in ctx.receive():
        print(f"{msg.sender_did}: {msg.content}")
        break

    await ctx.close()

asyncio.run(main())
```

### TypeScript

```typescript
import { Identity, Context } from "@scp/sdk";

const identity = await Identity.create({ custody: "platform" });
console.log(`DID: ${identity.did}`);

const ctx = await Context.create(identity, {
  ceiling: ["msg:send", "msg:receive"],
  ttl: 3600,
});

await ctx.send(new TextEncoder().encode("Hello from SCP"));

for await (const msg of ctx.receive()) {
  console.log(`${msg.senderDid}: ${msg.content}`);
  break;
}

await ctx.close();
```

### Swift

```swift
import SCP

let identity = try await Identity.create(custody: "platform")
print("DID: \(identity.did)")

let ctx = try await Context.create(
    identity: identity,
    params: ContextParams(
        ceiling: ["msg:send", "msg:receive"],
        ttl: 3600
    )
)

try await ctx.send(Data("Hello from SCP".utf8))

for await msg in ctx.messages {
    print("\(msg.senderDid): \(String(data: msg.content, encoding: .utf8)!)")
    break
}

try await ctx.close()
```

### Kotlin

```kotlin
import com.limn.scp.Identity
import com.limn.scp.Context
import kotlinx.coroutines.flow.first

suspend fun main() {
    val identity = Identity.create(custody = "platform")
    println("DID: ${identity.did}")

    val ctx = Context.create(
        identity = identity,
        params = mapOf(
            "ceiling" to listOf("msg:send", "msg:receive"),
            "ttl" to 3600,
        ),
    )

    ctx.send("Hello from SCP".toByteArray())

    val msg = ctx.receiveFlow().first()
    println("${msg.senderDid}: ${String(msg.content)}")

    ctx.close()
}
```

---

## Next Steps

- **Per-language READMEs** with detailed API coverage, type checking setup, and publishing:
  - [Python SDK](../../bindings/python/README.md)
  - [TypeScript SDK](../../bindings/typescript/README.md)
  - [Swift SDK](../../bindings/swift/README.md)
  - [Kotlin SDK](../../bindings/kotlin/README.md)
- **Examples** -- each SDK ships runnable example scripts covering messaging, tool invocation, MCP integration, and multi-agent coordination. See the `examples/` directory in each binding.
- **API surface sketch** -- the full protocol API design across identity, contexts, governance, tools, trust, and transport: [`.docs/sketch.md`](../../.docs/sketch.md)
- **Architecture guide** -- how the SDK layers, crate layout, and binding strategy fit together: [`docs/guides/architecture.md`](./architecture.md)
