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

`identityCreate` takes a `CustodyType` and carries no default, so a caller names
the key store and this SDK names none for them. §3.2.2 of the identity spec,
"The Custody Vocabulary", states the two values `CustodyType` carries.
`ENCRYPTED_FILE` (`"encrypted_file"`) selects the on-disk key store SCP
implements, which derives the file key with Argon2id and encrypts
`$HOME/.scp/keys.bin` with AES-256-GCM. `OS_KEYSTORE` (`"os_keystore"`) selects
the operating system's own key store, which SCP reaches through the platform
key-custody callback you supply. Every other string throws
`ScpException.Validation` carrying `SCP-VALID-7005`, and that includes
`"platform"`, `"software"`, `"file"`, `"platform_managed"`, and `"hardware"`.

`scp.identityCreate(custody = CustodyType.OS_KEYSTORE)` throws
`ScpException.Identity` carrying `SCP-IDENT-1003`, because that call supplies no
provider and the bridge falls back to neither the encrypted key file nor an
in-memory store. Reaching Android Keystore runs through
`scp.identityCreateWithCustody(provider)` instead. The private key material
never crosses into the native core, because the core delegates every
cryptographic operation back to your callbacks (ADR-006, the platform
abstraction).

A build carrying the bridge's `testing` cargo feature additionally accepts the
raw string `"in_memory"`, which reaches the test-only in-memory key store. No
`CustodyType` entry spells it, a test that needs it passes the raw string to the
UniFFI `Scp` object, and a released build throws `ScpException.Identity`
carrying `SCP-IDENT-1008`.

The `scp-kt-android` module ships `AndroidKeyCustody` over Android Keystore and
`UniffiKeyCustody`, which presents it as the `uniffi.scp.KeyCustodyProvider`
this method takes:

```kotlin
val custody = AndroidKeyCustody(context)
val identity = scp.identityCreateWithCustody(UniffiKeyCustody(custody))
```

The two interfaces name the same eleven operations and declare them
differently — `AndroidKeyCustody` implements
`works.limn.scp.android.platform.KeyCustodyProvider`, which takes a `KeyHandle`
where the UniFFI interface takes an id string, and declares
`publicKey(KeyHandle)` where the UniFFI interface declares
`getPublicKey(String)`. `UniffiKeyCustody` converts between them in one place.

`AndroidKeyCustody` does not put every key in Android Keystore: it holds Ed25519
keys in Keystore only on API 33 and above, it generates software Ed25519 keys
through Bouncy Castle on API 26 to 32 and persists their seeds in
`EncryptedSharedPreferences`, and it manages every X25519 key in software,
because Android Keystore supports X25519 key agreement at no API level. To reach
a different store, implement `uniffi.scp.KeyCustodyProvider` yourself and pass
it in.

## The published custody value

`scp.identityPublishedCustody(did)` returns the published-vocabulary custody
value for that DID's `#active` key, read off the backend running in this
process. §3.2.2 states that value as whether the key can leave its store and
which factor unlocks it: `"non-extractable-biometric"`,
`"non-extractable-pin"`, or `"extractable-passphrase"`. It returns `null` when
the backend holding the `#active` key reports a pair the published vocabulary
states no value for.

The bridge derives the value from the running backend, so the value states what
that backend reported. `KeyCustodyProvider.keyIsExtractable` and
`KeyCustodyProvider.unlockFactor` answer the two questions for an injected
provider.

The call reads no DID document. Nothing SCP ships writes a custody attestation
into one — `ScpKeyCustodyAttestation::derive` and
`DidDocument::set_custody_attestation` have no caller outside tests — so a
stranger resolving the DID finds no custody service entry, and this call answers
only for an identity this instance created. Section 3.2.2.1 of the identity spec
records that as divergence D18, and its open question OQ-17 asks which component
writes the entry.

It throws `ScpException.Identity` carrying `SCP-IDENT-1001` for a DID this
instance retains no custody for, and the same code when the injected provider
throws while answering either question.

`AndroidKeyCustody` answers both questions on its own interface, which
`UniffiKeyCustody` presents to `identityCreateWithCustody` (see "Key custody"
above). It answers `false` to the first for a TEE-backed key, whose
private bytes `exportSigningKeyBytes` refuses to release, and `true` for a
Bouncy Castle key, whose 32-byte seed it copies out. It answers `"unprotected"`
to the second for both, because `KeystoreKeyOps.generateEd25519` builds its
`KeyGenParameterSpec` with `setUserAuthenticationRequired(false)` and the
`EncryptedSharedPreferences` master key comes from `MasterKeys.AES256_GCM_SPEC`,
which requires no user authentication either. §3.2.2 states no published value
for either pair, so a participant on this adapter publishes no custody
attestation.

## No shipped build creates an identity yet

`identityCreateWithCustody` throws `ScpException.Identity` carrying
`SCP-IDENT-1059` on every released build, and
`identityCreate(custody = CustodyType.ENCRYPTED_FILE)` throws it too once
`SCP_KEY_PASSPHRASE` is set. Section 9.7.4.1 of the
security model, pre-rotation key custody, makes every identity commit a
pre-rotation commitment when it is created. That commitment needs a
`PreRotationCustody` backend, and the only implementation is the test-harness
`InMemoryPreRotationCustody`, which the bridge's `testing` feature severs from
production, so
`crates/scp-ffi/uniffi/src/bridge.rs` returns the typed error rather than
minting the test double. ADR-062, capability injection and prove-absent dev
backends, records that state as accepted in its §Decision 6 and holds the real
backend out of its own scope. The Quick Start above therefore runs against a
build that enables the `testing` feature.

Two separate gaps produce those codes, and closing one does not close the
other. `SCP-IDENT-1003`, `SCP-IDENT-1008`, and `SCP-VALID-7005` say that the
custody value you passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
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
