# SCP Kotlin SDK

> `works.limn:scp-kt` -- Shared Context Protocol for Kotlin

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Built on Rust via UniFFI with Kotlin coroutines.

## Install

```kotlin
// build.gradle.kts
dependencies {
    implementation("works.limn:scp-kt:0.1.0")
}
```

## Quick Start

```kotlin
import works.limn.scp.Identity
import works.limn.scp.Context
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
| `OutletInvocation.kt` | Register and invoke a outlet with test vectors |
| `McpIntegration.kt` | Expose SCP outlets via MCP JSON-RPC server |
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

## Publishing

### Local

Publish to Maven Local for integration testing:

```bash
./gradlew publishToMavenLocal
```

Artifacts are written to `~/.m2/repository/works/limn/scp-kt/`.

### Maven Central (Release)

Release publishing uses Sonatype OSSRH staging. Required environment variables:

| Variable | Purpose |
|----------|---------|
| `MAVEN_CENTRAL_USERNAME` | Sonatype OSSRH username |
| `MAVEN_CENTRAL_TOKEN` | Sonatype OSSRH token |
| `GPG_KEY_ID` | GPG signing key ID (short form) |
| `GPG_PRIVATE_KEY` | ASCII-armored GPG private key |
| `GPG_PASSPHRASE` | GPG key passphrase |

```bash
./gradlew publish
```

This deploys to the Sonatype staging repository. After deploy:

1. Log in to https://s01.oss.sonatype.org
2. Find the staging repository under "Staging Repositories"
3. Close the repository (runs Maven Central validation rules)
4. Release the repository (promotes to Maven Central)

### Snapshots

Snapshot versions (version ending in `-SNAPSHOT`) publish to the Sonatype snapshots repository automatically when using `./gradlew publish`.

### CI Pipeline

Release publishing is triggered by tagged releases in CI. The workflow:

1. CI detects a version tag (e.g., `v0.1.0`)
2. Runs `./gradlew build` (ktlint + detekt + compile + test)
3. Runs `./gradlew publish` with signing credentials from GitHub Actions secrets
4. Staging repository is closed and released via Sonatype API

## Source

- Scaffold: `.docs/scaffold/kotlin.md`
- Standards: `.docs/standards/kotlin.md`
- API sketch: `.docs/sketch.md`
