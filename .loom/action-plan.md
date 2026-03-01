# Action Plan: Remaining Fixes for loom/main-0228-1657

Bugs 2–8 from the original action plan (below) are resolved. Bug 1 (routing ID derivation) has a fix that's functionally wrong — the HMAC is keyed with the public DID string, providing zero secrecy. Three additional issues in the same code block also need fixing. All changes are in `crates/scp-ffi/`.

---

## 1. Replace public DID key with per-identity random secret in HMAC derivation

**File:** `crates/scp-ffi/src/context.rs:462-502`
**Problem:** The current fix uses `HMAC-SHA256(identity_did.as_bytes(), context_id || "scp-routing")`. DIDs are public identifiers — anyone who knows the DID and context_id can recompute the routing ID. This is functionally equivalent to a plain hash, providing zero pseudonym unlinkability. A relay operator who knows a participant's DID can correlate all their contexts.

The correct derivation (§9.10.4, `pseudonym.rs:8-11`) uses private key material via `KeyCustody::derive_pseudonym`. But `KeyCustody` isn't stored in the runtime registry — `py_identity_create` (`identity.rs:242-260`) creates an `InMemoryKeyCustody` per-call and discards it. Only the DID string survives in `PyIdentity`. Wiring KeyCustody into the runtime is out of scope for this fix.

**Fix:** Generate a 32-byte random secret per identity DID and store it in the runtime registry. Use this as the HMAC key. The secret never leaves the client — it provides actual unlinkability until `KeyCustody` is wired in.

In `crates/scp-ffi/src/runtime.rs`, add a `DashMap<String, [u8; 32]>` for per-identity routing secrets:

```rust
static IDENTITY_ROUTING_SECRETS: OnceLock<DashMap<String, [u8; 32]>> = OnceLock::new();

pub fn get_or_create_routing_secret(identity_did: &str) -> [u8; 32] {
    let map = IDENTITY_ROUTING_SECRETS.get_or_init(DashMap::new);
    *map.entry(identity_did.to_owned())
        .or_insert_with(|| {
            let mut secret = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
            secret
        })
}
```

In `crates/scp-ffi/src/context.rs`, replace the HMAC key:

```rust
let routing_secret = crate::runtime::get_or_create_routing_secret(identity_did);
let mut mac = HmacSha256::new_from_slice(&routing_secret)
    .map_err(|e| PyRuntimeError::new_err(format!("HMAC initialization failed: {e}")))?;
mac.update(context_id.as_bytes());
mac.update(b"scp-pseudonym");
let routing_id: [u8; 32] = mac.finalize().into_bytes().into();
```

Update the comment to explain:
- This is an interim derivation using a per-identity random secret (not the spec's key material)
- The secret is in-memory only and will not match across process restarts
- When `KeyCustody` is wired into the runtime, replace with `scp_core::envelope::pseudonym::derive_pseudonym`

**References:**
- Correct derivation: `crates/scp-core/src/envelope/pseudonym.rs:8-11`
- `KeyCustody` trait: `crates/scp-platform/src/traits.rs` — `derive_pseudonym` method
- Spec: `.docs/specs/09-security-model.md:492` (§9.10.4 metadata privacy)
- Identity module: `crates/scp-ffi/src/identity.rs:242-260` — `InMemoryKeyCustody` created per-call, not stored
- `PyIdentity` struct: `crates/scp-ffi/src/identity.rs:56-63` — only stores DID string + custody type string

---

## 2. Change domain separator from `"scp-routing"` to `"scp-pseudonym"`

**File:** `crates/scp-ffi/src/context.rs:478`
**Problem:** The current fix uses `"scp-routing"` but the spec (§9.10.4) and `pseudonym.rs:9` use `"scp-pseudonym"`. When `KeyCustody` is wired in, only the HMAC key should change — not the domain separator. Using a different separator now means routing IDs computed today will silently stop matching when the derivation is upgraded, breaking known-context entries.

**Fix:** Change `b"scp-routing"` to `b"scp-pseudonym"` on line 478. This is a one-character-class change in the `mac.update` call shown in fix #1 above (already included in that snippet).

**References:**
- `crates/scp-core/src/envelope/pseudonym.rs:9` — `context_id || "scp-pseudonym"`
- `.docs/specs/05-contexts.md:863` — broadcast uses `SHA-256(context_id)`, encrypted uses HMAC with `"scp-pseudonym"`

---

## 3. Replace `.expect()` with `.map_err()?` on HMAC initialization

**File:** `crates/scp-ffi/src/context.rs:476`
**Problem:** `HmacSha256::new_from_slice(...).expect("HMAC accepts any key length")` panics across the PyO3 FFI boundary. While HMAC-SHA256 does accept any key length (so this won't panic in practice), the project standard is no `unwrap`/`expect` in lib code — clippy `deny(clippy::unwrap_used, clippy::expect_used)` is configured.

**Fix:** Already shown in the snippet in fix #1:
```rust
.map_err(|e| PyRuntimeError::new_err(format!("HMAC initialization failed: {e}")))?;
```

---

## 4. Add comment documenting passphrase String residual in JVM heap

**File:** `bindings/kotlin/scp-sdk-kotlin-android/src/main/kotlin/com/limn/scp/android/platform/AndroidStorage.kt:78-85`
**Problem:** The `encryptionKey.fill(0)` in the `finally` block correctly zeroes the ByteArray, but line 79 creates `val passphrase = String(encryptionKey, Charsets.ISO_8859_1)` — a JVM String that is immutable and cannot be zeroed. The passphrase copy will persist in the JVM heap until GC. The fix as written overstates its protection.

**Fix:** Add a comment above the `String(...)` construction:

```kotlin
// NOTE: The String copy of the passphrase cannot be zeroed due to JVM String
// immutability. The ByteArray source (encryptionKey) is zeroed in the finally
// block. The real protection is TEE-backed key derivation — the passphrase is
// useless without the Android Keystore key. If SQLCipher adds a char[] or
// ByteArray overload for getWritableDatabase, prefer that and zero after use.
```

---

## Verification

After all fixes:
1. `cargo check --workspace` — compiles clean
2. `cargo test --workspace --exclude scp-ffi` — all tests pass
3. Grep `crates/scp-ffi/src/context.rs` for `"scp-pseudonym"` — domain separator matches spec
4. Grep `crates/scp-ffi/src/context.rs` for `identity_did.as_bytes()` in HMAC key position — should be gone, replaced with `routing_secret`
5. Grep `crates/scp-ffi/src/context.rs` for `.expect(` — should be gone
6. Grep `crates/scp-ffi/src/runtime.rs` for `IDENTITY_ROUTING_SECRETS` — new registry exists
7. Read the AndroidStorage passphrase comment — documents the JVM limitation


# Action Plan: Outstanding Bugs from loom/main-0228-1657

All bugs below were found by review agents but misclassified as LEARNINGs or have incorrect fixes. They must be resolved before merging.

---

## 1. Routing ID derivation uses SHA-256(context_id) — wrong for encrypted contexts

**Origin:** Bad fix for original bug 1 ("KNOWN_CONTEXTS never populated"). Commit `8ff8020` correctly added the `register_known_context()` call in `py_context_create` — that call stays. But the routing ID derivation passed to it is wrong, which means relay probes still never match real envelopes. The original bug is technically "fixed" (the registry is populated) but functionally **still broken** (probes return nothing because the routing IDs don't match what's on the relay).

**Introduced:** commit `8ff8020` (`fix(scp-ffi): wire KNOWN_CONTEXTS registration and fix Python dict access`)
**File:** `crates/scp-ffi/src/context.rs:466-469`
**Problem:** Uses `SHA-256(context_id)` as the routing ID. This is the **broadcast context** derivation. For encrypted contexts, the protocol requires per-identity pseudonyms via `HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`.

Consequences:
- All members of a context share the same routing ID — destroys participant unlinkability
- Anyone with the context_id can derive the routing ID — relay operators can correlate activity
- Relay probes will never match real envelopes (stored under HMAC-derived pseudonyms) — relay path is **still dead code**

**Fix:** Keep the `register_known_context()` call, replace the routing ID derivation. Use `scp_core::envelope::pseudonym::derive_pseudonym` with the identity key material. If `KeyCustody` isn't wired into the FFI bridge yet, use `HMAC-SHA256(identity_did, context_id || "scp-routing")` as a minimum (at least produces per-identity IDs).

**References:**
- Correct derivation: `crates/scp-core/src/envelope/pseudonym.rs:8-11` — `seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`, `pseudonym_keypair = Ed25519_keygen(seed[0..32])`, routing_id = public key
- `KeyCustody::derive_pseudonym` trait: `crates/scp-core/src/envelope/pseudonym.rs:38-44`
- Broadcast vs encrypted routing: `.docs/specs/05-contexts.md:863` — "This differs from encrypted context routing where `routing_id` is derived via HKDF from identity key material (§9.10.4)"
- Broadcast derivation (what the bad fix used): `.docs/specs/05-contexts.md:863` — `routing_id = SHA-256(context_id)` — publicly derivable, for broadcast only
- Metadata privacy model: `.docs/specs/09-security-model.md:492`
- Pseudonym unlinkability test: `.docs/specs/16-test-infrastructure.md:892`
- `RoutingId` type: `crates/scp-transport/src/traits.rs:62-71`
- `KnownContext` struct: `crates/scp-ffi/src/runtime.rs`
- Relay probe consumer: `crates/scp-ffi/src/mcp.rs` — `probe_relay_for_known_contexts`, `py_mcp_load_contexts`

**Also fix in the same commit (all introduced in `8ff8020`):**
- Change `relay_url` from `String` to `Option<String>` in `KnownContext` (`runtime.rs`) — `unwrap_or_default()` produces `""` which is ambiguous. Propagate the `Option` through `py_mcp_load_contexts`.
- Log instead of silently swallowing `py_transport_status()` errors (`.ok()` on `context.rs:472`).
- Propagate clock error instead of `unwrap_or(0)` for `last_seen` (`context.rs:481-484`).

---

## 2. AndroidStorage missing `setRandomizedEncryptionRequired(false)` on GCM KeyGenParameterSpec

**Introduced:** commit `775403b` (`feat(kotlin): implement Android Storage with TEE-backed SQLCipher (SCP-113)`)
**File:** `kotlin/scp-sdk-android/src/main/kotlin/works/limn/scp/android/AndroidStorage.kt`
**Problem:** GCM mode with AES requires `setRandomizedEncryptionRequired(false)` on the `KeyGenParameterSpec.Builder`. Without it, Android Keystore will crash at runtime on real devices. JVM unit tests don't exercise the real Keystore so this is invisible in CI.

**Fix:** Add `.setRandomizedEncryptionRequired(false)` to the KeyGenParameterSpec builder chain.

**References:**
- Android KeyGenParameterSpec docs: `setRandomizedEncryptionRequired(false)` is required for GCM because GCM inherently provides randomization via IV
- ADR-027 key custody requirements: `.docs/adrs/phase-6.md`

---

## 3. Derived passphrase ByteArray not zeroed after SQLCipher database open

**Introduced:** commit `775403b` (SCP-113)
**File:** `kotlin/scp-sdk-android/src/main/kotlin/works/limn/scp/android/AndroidStorage.kt`
**Problem:** The TEE-derived passphrase bytes remain in memory after `SupportSQLiteDatabase` is opened. Key material should be zeroed immediately after use.

**Fix:** After the passphrase is consumed by SQLCipher, call `passphrase.fill(0)` (or equivalent zeroing).

**References:**
- OWASP Mobile Security: key material must be zeroed after use to limit exposure window
- `.docs/specs/09-security-model.md` — defense-in-depth principle

---

## 4. SQL LIKE prefix not escaped for `%` and `_` wildcards

**Introduced:** commit `775403b` (SCP-113)
**File:** `kotlin/scp-sdk-android/src/main/kotlin/works/limn/scp/android/AndroidStorage.kt`
**Problem:** `listByPrefix` / `deletePrefix` pass the prefix directly into a SQL LIKE clause without escaping `%` and `_` characters. A prefix containing these characters matches unintended rows.

**Fix:** Escape `%` → `\%` and `_` → `\_` in the prefix before building the LIKE pattern. Add `ESCAPE '\'` to the SQL clause.

**References:**
- Storage trait contract: `.docs/specs/17-persistence-and-storage.md:484` — conformance suite tests prefix operations
- `StorageProvider` trait in scp-core for expected semantics

---

## 5. deletePrefix uses non-atomic two-step DELETE + SELECT changes()

**Introduced:** commit `775403b` (SCP-113)
**File:** `kotlin/scp-sdk-android/src/main/kotlin/works/limn/scp/android/AndroidStorage.kt`
**Problem:** `deletePrefix` does a DELETE followed by `SELECT changes()` as separate statements. Between them, another thread could run a DELETE, inflating the count. Not atomic.

**Fix:** Wrap in a transaction, or use `RETURNING` if the SQLCipher version supports it.

---

## 6. Error messages leak key names and exception details across FFI

**Introduced:** commit `775403b` (SCP-113)
**File:** `kotlin/scp-sdk-android/src/main/kotlin/works/limn/scp/android/AndroidStorage.kt`
**Problem:** Error messages include raw key names and Java exception details that cross the FFI boundary into caller context. Could leak internal state.

**Fix:** Sanitize error messages at the FFI boundary — return error codes/categories instead of raw exception text.

**References:**
- `.docs/specs/09-security-model.md` — error messages must not leak internal state across trust boundaries

---

## 7. StorageProvider method names diverge from UniFFI interface

**Introduced:** commit `775403b` (SCP-113)
**File:** `kotlin/scp-sdk-android/src/main/kotlin/works/limn/scp/android/AndroidStorage.kt`
**Problem:** Uses `store`/`retrieve` but UniFFI bindings expect `set`/`get`. Will fail at integration time.

**Fix:** Rename to match UniFFI contract: `store` → `set`, `retrieve` → `get`.

**References:**
- UniFFI `StorageProvider` trait definition in scp-core
- ADR-027/028 Kotlin binding conventions: `.docs/adrs/phase-6.md`

---

## 8. Tests exercise InMemoryStorageProvider, not AndroidStorage

**Introduced:** commit `775403b` (SCP-113)
**File:** `kotlin/scp-sdk-android/src/test/kotlin/works/limn/scp/android/AndroidStorageTest.kt`
**Problem:** All 30 JVM tests run against `InMemoryStorageProvider`, not `AndroidStorage`. The SQL LIKE escaping bug (#4), non-atomic delete (#5), and Keystore crash (#2) are all undetectable. This is a known limitation of JVM-only testing, but at minimum the tests should be annotated as such.

**Fix:** Add a comment/annotation noting these are in-memory-only tests. Consider adding Robolectric or instrumented tests for the real implementation in a follow-up story.

---

## Verification

After all fixes:
1. `cargo check --workspace` — full workspace compiles
2. `cargo test --workspace --exclude scp-ffi` — all Rust tests pass
3. Verify `KnownContext.routing_id` derivation matches `scp_core::envelope::pseudonym` logic
4. Verify `KnownContext.relay_url` is `Option<String>` throughout
5. Grep for any remaining `h.context_id` patterns in `bindings/python/`
6. Grep for any remaining `unwrap_or_default()` on relay URLs
7. Grep for any remaining `store`/`retrieve` in AndroidStorage (should be `set`/`get`)
8. Verify passphrase zeroing in AndroidStorage
