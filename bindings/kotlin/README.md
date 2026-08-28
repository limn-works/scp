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
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.KeyCustodyProvider
import uniffi.scp.MemoryScope
import uniffi.scp.StorageConfig
import works.limn.scp.SCP

suspend fun main(keystore: KeyCustodyProvider) {
    // Storage selection is required — there is no default (spec §17.6).
    val scp = SCP.withStorage(StorageConfig.InMemory)

    // Create a cryptographic identity (DID). `keystore` is your own
    // KeyCustodyProvider over Android Keystore — see "Key custody" below. On a
    // released build this call throws SCP-IDENT-1059 — read "No shipped build
    // creates an identity yet" below before you run it.
    val identity = scp.identityCreateWithCustody(keystore)
    println("DID: ${identity.did()}")

    // Create an encrypted context
    val ctx = scp.contextCreate(
        identity = identity,
        params = ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("msg:send", "msg:receive"),
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

    // Send a message (MLS-encrypted, signed, provenance-tagged)
    scp.contextSend(
        handle = ctx,
        identity = identity,
        payload = "Hello from SCP".toByteArray(),
        spendingUcanJwt = null,
    )

    scp.contextClose(handle = ctx, identity = identity)
}
```

## Key custody

`identityCreate` takes a custody string, and the UniFFI bridge builds a key
store from one string only: `"in_memory"`, which it compiles under its `testing`
feature. A released build throws `ScpError.Identity` carrying `SCP-IDENT-1008`
for `"in_memory"`, and it throws `ScpError.Identity` carrying `SCP-IDENT-1003`
for `"platform"` and for `"software"`. No custody string reaches Android
Keystore.

Production key storage runs through `scp.identityCreateWithCustody(provider)`
instead. The private key material never crosses into the native core, because
the core delegates every cryptographic operation back to your callbacks
(ADR-006, the platform abstraction).

Implement `uniffi.scp.KeyCustodyProvider` yourself over Android Keystore and
pass it in. The `scp-kt-android` module ships `AndroidKeyCustody`, which stores
Ed25519 and X25519 key material in Android Keystore, but it implements
`works.limn.scp.android.platform.KeyCustodyProvider` — a different interface
from the `uniffi.scp.KeyCustodyProvider` this method takes, declaring
`publicKey(KeyHandle)` where the UniFFI interface declares
`getPublicKey(String)`. No adapter converts between the two, so
`AndroidKeyCustody` cannot be passed here until one lands.

## No shipped build creates an identity yet

`identityCreateWithCustody` throws `ScpError.Identity` carrying
`SCP-IDENT-1059` on every released build. `identityCreate` stops one step
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
build that enables the `testing` feature.

Two separate gaps produce those codes, and closing one does not close the
other. `SCP-IDENT-1003` and `SCP-IDENT-1008` say that the custody string you
passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
pre-rotation custody backend exists for any create path to use. A wired
platform provider clears the first gap; a real pre-rotation backend clears the
second.

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
