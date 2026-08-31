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
    // SCP-CAPSEL-8000). `"in_memory"` keeps key material in this process's
    // heap and loses it at exit, and a build without the `testing` feature
    // rejects it with SCP-IDENT-1008 — it is what this quick start uses and
    // what a shipped app must not. A shipped Android or iOS app names
    // `"platform"` and wires a KeyCustodyProvider through
    // `identityCreateWithCustody`, so the Android Keystore or the Secure
    // Enclave holds the key material and it never enters this process.
    val identity = scp.identityCreate(custody = "in_memory")
    println("DID: ${identity.did()}")

    // Create an encrypted context. `ContextParams` names every parameter a
    // prospective member reads before joining, so it carries no defaults. The
    // ceiling bounds every capability any member can ever hold, so it must
    // carry `context:close` for the `contextClose` call below to pass its
    // capability check.
    val ctx = scp.contextCreate(
        identity = identity,
        params = ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read", "messages:write", "context:close"),
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

### What this quick start needs, and why a published artifact refuses it

Two things above run only on a build that carries the `testing` cargo feature,
and both refusals are the protocol failing closed rather than minting a
test-only stand-in (`.docs/adrs/ADR-062-capability-injection.md` §Decision 6):

1. `identityCreate` commits a pre-rotation commitment at creation, which spec
   §9.7.4.1 §3 makes mandatory. No production `PreRotationCustody` backend
   exists yet, so a published artifact answers every `identityCreate` call —
   whichever custody you name — with `[SCP-IDENT-1059] no production
   pre-rotation custody backend available`. Issue #1729 and RFC #2130 track
   the real backend.
2. `"in_memory"` custody is a development affordance whose key material lives
   in this process's heap and dies with it. A build without `testing` answers
   `[SCP-IDENT-1008] in_memory custody is not available in this build`. A
   shipped app names `"platform"` and wires a `KeyCustodyProvider` through
   `identityCreateWithCustody`, so the Android Keystore holds the keys.

Build the native library with `testing` to run the quick start today:

```sh
cargo build -p scp-ffi-uniffi --features testing
./scripts/generate-uniffi-kotlin.sh --skip-build --features=testing
```

`ReadmeQuickStartTest` in `scp-kt`'s test source set runs the block above
verbatim, so this README stops drifting from what runs.

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
