# scp-sdk-kotlin-android — Android Platform Adapter

## Overview

Android-specific platform trait implementations for SCP. Implements the four UniFFI callback interfaces (`KeyCustodyProvider`, `DeviceAttestationProvider`, `PushProvider`, `StorageProvider`) using Android's native platform security stack. See ADR-027 in `.docs/adrs/phase-6.md`.

## Architecture

Each platform trait is a Kotlin class that implements a UniFFI-generated callback interface. The Rust engine calls these via UniFFI's callback mechanism. All classes accept an Android `Context` parameter for platform API access.

| File | Trait | Platform API | Story |
|------|-------|-------------|-------|
| `AndroidDeviceAttestation.kt` | `DeviceAttestationProvider` | Play Integrity Standard API | SCP-111 |
| `AndroidKeyCustody.kt` | `KeyCustodyProvider` | Android Keystore (Ed25519 API 33+, Bouncy Castle fallback) | SCP-110 |
| `AndroidPushProvider.kt` | `PushProvider` | Firebase Cloud Messaging | SCP-112 |
| `AndroidStorage.kt` | `StorageProvider` | SQLCipher + TEE-derived AES-256 key | SCP-113 |
| `PlatformAdapter.kt` | Factory | Constructs and injects all four providers | SCP-114 |

## Gotchas

### UniFFI method naming: snake_case -> camelCase

The Rust `DeviceAttestationProvider` trait has `assert_request(request_hash)`. UniFFI generates Kotlin with camelCase: `assertRequest(requestHash)`. The ADR-027 code sample uses `assert()` which is **incorrect** — always check the UniFFI Rust trait definition in `crates/scp-ffi/uniffi/src/lib.rs` for authoritative method signatures.

### Shared types live in Types.kt

All shared types (`ScpException`, `WakeSignal`, `KeyType`, `CustodyType`, `KeyHandle`, `PseudonymKeyHandle`, `DestructionAttestation`, `DestructionMethod`) and trait interfaces (`KeyCustodyProvider`, `DeviceAttestationProvider`, `PushProvider`, `StorageProvider`) are defined in `Types.kt`. Do NOT define these types locally in adapter files. When UniFFI-generated bindings are available, replace `Types.kt` with the generated types.

`ScpException` uses the property name `code` (not `errorCode`). `WakeSignal` entries use UPPER_CASE (`PULL`, not `Pull`).

### android.util.Base64 in unit tests

`android.util.Base64` is not available in pure JVM unit tests. Tests that call `buildClientDataJSON()` or `computeNonce()` require either:
- Robolectric (provides Android framework stubs)
- Moving to `androidTest/` for instrumentation execution
- A Base64 shim

### Null Context in unit tests

The `AndroidDeviceAttestation` constructor requires a non-null `android.content.Context`. For unit testing deterministic helpers (`buildClientDataJSON`, `computeNonce`) that don't use the context, an unsafe null cast (`(null as Any?) as Context`) works at the JVM level. Integration tests on real devices should use `ApplicationProvider.getApplicationContext()`.

### Play Integrity requires real device

Play Integrity API calls fail on emulators and devices without Google Play Services. Unit tests cover deterministic logic only; integration tests require physical hardware.

### Android Keystore AES-GCM requires setRandomizedEncryptionRequired(false) for deterministic IV

Android Keystore enforces randomized encryption by default for GCM keys. If you use a fixed/caller-supplied IV (as `AndroidStorage.getOrCreateStorageKey()` does for deterministic passphrase derivation), you **must** call `.setRandomizedEncryptionRequired(false)` on the `KeyGenParameterSpec.Builder`. Without this, `Cipher.init()` throws `InvalidAlgorithmParameterException` at runtime. This is invisible to JVM unit tests since they cannot use the real Android Keystore -- it only manifests on actual devices.

### StorageProvider method names diverge from UniFFI callback interface

The Kotlin `StorageProvider` interface in `Types.kt` uses `store()`/`retrieve()` but the UniFFI `StorageProvider` callback interface in `crates/scp-ffi/uniffi/src/lib.rs` uses `set()`/`get()`. When UniFFI-generated bindings replace `Types.kt`, `AndroidStorage.kt` will need method renames (`store` -> `set`, `retrieve` -> `get`). The UniFFI trait also uses `async` methods returning `Result<T, ScpError>` while the Kotlin interface uses synchronous methods with exceptions.

### SQL LIKE wildcards in prefix queries

`listKeys()` and `deletePrefix()` use SQL `LIKE ? ` with `"$prefix%"`. The `%` and `_` characters in SQLite LIKE are wildcards. If storage keys ever contain these characters, prefix queries will match unintended keys. The in-memory test double uses `startsWith` which does not exhibit this behavior -- test and production semantics diverge here. Use `ESCAPE` clauses or range queries if key namespaces evolve to include these characters.

## Build

```bash
# From bindings/kotlin/
./gradlew :scp-sdk-kotlin-android:build
./gradlew :scp-sdk-kotlin-android:test

# Requires Android SDK, Kotlin, Gradle (available via mise)
```

## Dependencies (from build.gradle.kts)

- `com.google.android.play:integrity:1.4.0` — Play Integrity API
- `org.bouncycastle:bcprov-jdk18on:1.80` — Software Ed25519 fallback
- `com.google.firebase:firebase-messaging:24.1.0` — FCM push
- `net.zetetic:sqlcipher-android:4.6.1` — Encrypted storage
- `androidx.security:security-crypto:1.1.0-alpha06` — EncryptedSharedPreferences
- `org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0` — Coroutines
- `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0` — Android dispatcher

## Standards

Follow `.docs/standards/kotlin.md` for code style, naming, and testing conventions. Key rules:
- All I/O operations are `suspend` functions
- Blocking FFI calls wrapped in `withContext(Dispatchers.IO)`
- JUnit 5 with backtick-quoted test names
- `kotlinx.coroutines.test.runTest` for suspend function tests
