# SCP Kotlin SDK

> `com.limn:scp-sdk-kotlin` -- Shareable Context Protocol for Kotlin

Cryptographic identity, encrypted contexts, capability-based auth, and tool invocation for AI agents. Built on Rust via UniFFI with Kotlin coroutines.

## Install

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.limn:scp-sdk-kotlin:0.1.0")
}
```

## Quick Start

```kotlin
import com.limn.scp.Identity
import com.limn.scp.Context
import kotlinx.coroutines.flow.first

suspend fun main() {
    // Create a cryptographic identity (DID)
    val identity = Identity.create(custody = "platform")
    println("DID: ${identity.did}")

    // Create an encrypted context
    val ctx = Context.create(
        identity = identity,
        params = mapOf(
            "ceiling" to listOf("msg:send", "msg:receive"),
            "ttl" to 3600,
        ),
    )

    // Send a message (MLS-encrypted, signed, provenance-tagged)
    ctx.send("Hello from SCP".toByteArray())

    // Receive messages
    val msg = ctx.receiveFlow().first()
    println("${msg.senderDid}: ${String(msg.content)}")

    ctx.close()
}
```

## Requirements

- Kotlin >= 2.0
- JVM >= 11
- kotlinx-coroutines-core

## API Reference

Generated from source via KDoc / Dokka. Build locally:

```bash
./gradlew dokkaHtml
```

Published API docs are generated on every release by CI.

## Examples

See [`examples/`](./examples/) for runnable code:

| File | Description |
|------|-------------|
| `BasicMessaging.kt` | Create identity, context, send/receive messages |
| `ToolInvocation.kt` | Register and invoke a tool with test vectors |
| `McpIntegration.kt` | Expose SCP tools via MCP JSON-RPC server |
| `MultiAgent.kt` | Coordinate multiple agents in a shared context |

## Error Handling

All exceptions extend `ScpException` with a machine-readable `code` field:

```kotlin
try {
    ctx.send(payload)
} catch (e: ContextException) {
    println("[${e.code}] ${e.message}")
}
```

## Source

- Scaffold: `.docs/scaffold/kotlin.md`
- Standards: `.docs/standards/kotlin.md`
- API sketch: `.docs/sketch.md`
