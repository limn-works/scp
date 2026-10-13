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

This quick start runs only with a native library built with the `testing` feature (`./gradlew :scp-kt:test -Pscp.uniffi.cargoFeatures=testing` builds one). A release build has no pre-rotation custody backend, so it refuses every identity creation with `SCP-IDENT-1059` (ADR-062 §Decision 6). Set `SCP_KEY_PASSPHRASE` before you run it: the identity's keys go to `$HOME/.scp/keys.bin`, sealed under that passphrase.

```kotlin
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.StorageConfig
import works.limn.scp.CustodyType
import works.limn.scp.SCP

suspend fun main() {
    // Every call goes through an SCP instance, which takes a required storage backend.
    val scp = SCP(StorageConfig.InMemory)

    // Create a cryptographic identity (DID) whose keys live in $HOME/.scp/keys.bin,
    // sealed under the SCP_KEY_PASSPHRASE environment variable.
    val identity = scp.identityCreate(custody = CustodyType.ENCRYPTED_FILE)
    println("DID: ${identity.did()}")

    // Create an encrypted context that this identity administers.
    val ctx =
        scp.contextCreate(
            identity = identity,
            params =
                ContextParams(
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
                    pseudonymRotation = null,
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

`scp-kt/src/test/kotlin/works/limn/scp/quickstart/ReadmeQuickStart.kt` holds a copy of the block above, and `ReadmeQuickStartTest` checks that the copy matches this file and runs it.

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

SCP calls throw subclasses of `uniffi.scp.ScpException`, such as `ScpException.Context`, each with `msg` and a machine-readable `code`. Here `contextSend` to a context that has already been closed throws `ScpException.Context`, and the function returns its code.

```kotlin
import uniffi.scp.ContextHandle
import uniffi.scp.Identity
import uniffi.scp.ScpException
import works.limn.scp.SCP

/** Sends [payload] to [ctx]; returns the error code when the context rejects the send. */
suspend fun sendReportingRejection(
    scp: SCP,
    ctx: ContextHandle,
    identity: Identity,
    payload: ByteArray,
): String? =
    try {
        scp.contextSend(handle = ctx, identity = identity, payload = payload, spendingUcanJwt = null)
        null
    } catch (e: ScpException.Context) {
        println("[${e.code}] ${e.msg}")
        e.code
    }
```

`scp-kt/src/test/kotlin/works/limn/scp/quickstart/ReadmeErrorHandling.kt` holds a compiled copy of this block, and `ReadmeQuickStartTest` checks it against this file and calls it on a closed context.

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
