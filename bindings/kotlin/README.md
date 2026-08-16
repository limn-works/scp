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
import works.limn.scp.CeilingPolicy
import works.limn.scp.ContextMode
import works.limn.scp.ContextParams
import works.limn.scp.GovernanceModel
import works.limn.scp.MemoryScope
import works.limn.scp.SCP
import works.limn.scp.StorageConfig

suspend fun main() {
    // Every call routes through an SCP instance (ADR-048). Name a storage
    // backend: this factory has no default.
    val scp = SCP(StorageConfig.InMemory)

    // Create a cryptographic identity (DID). Name a custody backend too —
    // `identityCreate` has no default either (spec §17.17.1,
    // SCP-CAPSEL-8000).
    val identity = scp.identityCreate(custody = "platform")
    println("DID: ${identity.did}")

    // Create an encrypted context. `ContextParams` names every parameter a
    // prospective member reads before joining, so it carries no defaults.
    val ctx = scp.contextCreate(
        identity = identity,
        params = ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read", "messages:write"),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 3600uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
        ),
    )

    // Send a message (MLS-encrypted, signed, provenance-tagged).
    scp.contextSend(
        handle = ctx,
        identity = identity,
        payload = "Hello from SCP".toByteArray(),
        spendingUcanJwt = null,
    )

    scp.contextClose(handle = ctx, identity = identity)
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
