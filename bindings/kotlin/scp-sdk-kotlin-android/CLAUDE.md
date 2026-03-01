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

`android.util.Base64` is not available in pure JVM unit tests. `AndroidDeviceAttestationTest` uses Robolectric (`@RunWith(RobolectricTestRunner::class)` + JUnit 4) to provide real `android.util.Base64` implementations on the host JVM. Other test files that don't need Android framework classes stay on JUnit 5.

### Context in unit tests

`AndroidDeviceAttestationTest` uses `ApplicationProvider.getApplicationContext()` from `androidx.test:core` (provided by Robolectric) for a real application context. `AndroidPushProviderTest` uses a null cast (`(null as Any?) as Context`) because it only needs the type, not a real context — this works with `isReturnDefaultValues = true` in testOptions. Integration tests on real devices should use `ApplicationProvider.getApplicationContext()`.

### Play Integrity requires real device

Play Integrity API calls fail on emulators and devices without Google Play Services. Unit tests cover deterministic logic only; integration tests require physical hardware.

### SQLCipher 4.6+ package rename

The dependency `net.zetetic:sqlcipher-android:4.6.x` uses package `net.zetetic.database.sqlcipher.*`. The old artifact `net.zetetic:android-database-sqlcipher:4.5.x` used `net.sqlcipher.database.*`. Key API differences: no `SQLiteDatabase.loadLibs()` (use `System.loadLibrary("sqlcipher")` instead), passphrase passed via `SQLiteOpenHelper` constructor (not `getWritableDatabase(String)`), and `SQLiteOpenHelper` implements `androidx.sqlite.db.SupportSQLiteOpenHelper` (requires `androidx.sqlite:sqlite:2.2.0`).

### EdDSA key generation uses NamedParameterSpec, not EdDSAParameterSpec

For Android Keystore Ed25519 key generation (API 33+), use `NamedParameterSpec.ED25519` as the algorithm parameter spec. `EdDSAParameterSpec` is for specifying prehash mode and context bytes, not the curve. The constant `Ed25519` lives on `NamedParameterSpec`, not `EdDSAParameterSpec`.

### Android Keystore AES-GCM requires setRandomizedEncryptionRequired(false) for deterministic IV

Android Keystore enforces randomized encryption by default for GCM keys. If you use a fixed/caller-supplied IV (as `AndroidStorage.getOrCreateStorageKey()` does for deterministic passphrase derivation), you **must** call `.setRandomizedEncryptionRequired(false)` on the `KeyGenParameterSpec.Builder`. Without this, `Cipher.init()` throws `InvalidAlgorithmParameterException` at runtime. This is invisible to JVM unit tests since they cannot use the real Android Keystore -- it only manifests on actual devices.

### StorageProvider method names match UniFFI callback interface

The Kotlin `StorageProvider` interface in `Types.kt` uses `set()`/`get()` matching the UniFFI `StorageProvider` callback interface in `crates/scp-ffi/uniffi/src/lib.rs`. The Rust `Storage` trait in `scp-platform/src/traits.rs` uses `store()`/`retrieve()` internally, but the UniFFI/Kotlin boundary uses `set`/`get`. The UniFFI trait uses `async` methods returning `Result<T, ScpError>` while the Kotlin interface uses synchronous methods with exceptions.

### SQL LIKE wildcards in prefix queries

`listKeys()` and `deletePrefix()` escape `%`, `_`, and `\` wildcards via `escapeLikePrefix()` and use `ESCAPE '\'` clauses in SQL LIKE patterns. The in-memory test double uses `startsWith` which does not need escaping but has equivalent prefix-match semantics.

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
- `net.zetetic:sqlcipher-android:4.6.1` — Encrypted storage (package: `net.zetetic.database.sqlcipher.*`)
- `androidx.sqlite:sqlite:2.2.0` — Required companion for sqlcipher-android 4.6+
- `androidx.security:security-crypto:1.1.0-alpha06` — EncryptedSharedPreferences
- `org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0` — Coroutines
- `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0` — Android dispatcher

## Standards

Follow `.docs/standards/kotlin.md` for code style, naming, and testing conventions. Key rules:
- All I/O operations are `suspend` functions
- Blocking FFI calls wrapped in `withContext(Dispatchers.IO)`
- JUnit 5 with backtick-quoted test names (except Robolectric tests which require JUnit 4 `@RunWith`)
- `kotlinx.coroutines.test.runTest` for suspend function tests
