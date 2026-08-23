# SCP-1717 Pre-Rotation Custody Audit (2026-05-03)

Full crypto review of 21 commits on `origin/main..HEAD` for branch `worktree-scp-1717-wasm-rotate-key`.

## Architecture Summary

**Pivot:** From `pre_rotation_key: KeyHandle` on `ScpIdentity` (which violated spec §9.7.4.1 §3 storage isolation) to a dedicated `PreRotationCustody` trait threaded through every layer.

- `ScpIdentity` now matches main shape: only `pre_rotation_commitment: [u8; 32]` + `did: String` + 3 `KeyHandle`s for operational keys.
- New `PreRotationCustody` trait in `scp-platform`: 3 methods (`store_committed_pre_rotation_key`, `reveal_public_key`, `destroy_after_migration`) + diagnostic.
- New `PreRotationKeyHandle` newtype with NO `From<KeyHandle>` — type-system enforces isolation.
- `KeyCustody` gains `generate_ephemeral_ed25519_seed` and `import_ed25519_signing_key` (default-error for HSM-bound; software impls for `InMemoryKeyCustody`, `FileKeyCustody`, `SqliteKeyCustody`, `CallbackKeyCustody`).
- WASM bridge: `IdentityRecord::Local::pre_rotation_handle: u64` + separate `PRE_ROTATION_REGISTRY` thread-local.
- All 4 FFI bridges declare `Arc<InMemoryPreRotationCustody>` on the IdentityEntry — a **concrete testing type**, not polymorphic dispatch (#1729 follow-up).

## Findings

### HIGH — `verify_migration` does not bind `migration_proof.old_public_key` to `old_did`

**File:** `crates/scp-identity/src/dht.rs:1706-1815`

The function takes `old_did`, `old_document`, and `migration_proof.old_public_key` but never verifies they match. Step 1 only checks "this public key signed this digest." With `pre_rotation_proof = None` (the MODERATE assurance path), an attacker can:
1. Generate fresh `(att_priv, att_pub)`.
2. Set `migration_proof.old_public_key = att_pub`.
3. Sign the migration digest with `att_priv`.
4. Call `verify_migration(victim_did, victim_doc, attacker_new_did, ...)` → returns `true`.

The `Some` path is mitigated by step 2b (commitment binding) and 2c (revealed_key binding). The `None` path is wide open.

**Fix:** Add early check:
```rust
let did_pubkey = extract_public_key(old_did)?;
if did_pubkey != migration_proof.old_public_key {
    return Err(IdentityError::MigrationVerificationFailed(...));
}
```

`pub fn verify_migration` is exported from the crate root and may be wired through FFI bridges in future. Even if no SDK code calls it today, the contract is wrong.

### MEDIUM — Migration partial-failure orphan seed

**File:** `crates/scp-identity/src/dht.rs:1261-1275`

If `store_committed_pre_rotation_key` (step 5) succeeds and `destroy_after_migration` (step 6) fails, the new pre-rotation seed is orphaned in cold custody. On retry, the SDK uses the OLD handle (still resolvable), generating yet another orphan. The InMemoryPreRotationCustody and WASM `PRE_ROTATION_REGISTRY` cap at 10,000 entries; orphan accumulation could DoS migration.

### MEDIUM — Migration unrecoverable failure between destroy and import

**File:** `crates/scp-identity/src/dht.rs:1272-1280`

`destroy_after_migration` returns the bytes (step 6). If `import_ed25519_signing_key` fails (step 6 cont'd), `revealed_private` zeros on drop. The OLD pre-rotation key is permanently lost, the new `#0` was never installed, and the `alsoKnownAs` was already published (step 3). The migration is unrecoverable.

### MEDIUM — `rotated_at` unbounded

**File:** `crates/scp-identity/src/dht.rs:1706-1815`

No upper bound check. Should reject `rotated_at > now() + 5min` per spec §9.14 clock skew tolerance. Combined with the `old_public_key` binding gap, a stolen old `#0` could mint historical-looking migrations.

### MEDIUM — CallbackKeyCustody migration broken (production iOS/Android)

**File:** `crates/scp-ffi/uniffi/src/bridge.rs:459-485`

`CallbackKeyCustody::import_ed25519_signing_key` returns `PlatformError::Unsupported`. Identity creation works (commit 259ecb311 fixed `generate_ephemeral_ed25519_seed`), but `migrate_identity` fails at step 6. Production iOS/Android identities CANNOT migrate after Identity Key compromise — the primary purpose of pre-rotation per spec §9.12. Tracked in #1729.

### MEDIUM — CallbackKeyCustody substrate isolation incomplete

**File:** `crates/scp-ffi/uniffi/src/bridge.rs:435-457`

`generate_ephemeral_ed25519_seed` generates locally via `OsRng`, satisfying type isolation. But the seed bytes co-reside in the bridge process briefly with operational keys (which route through Apple Keychain / Android Keystore via callback). Spec §9.7.4.1 §3 requires separate "custody provider OR authentication flow." Type isolation: yes. Substrate isolation: no — bridge process holds both.

### LOW — Native `InMemoryPreRotationCustody::PreRotationKeyEntry` lacks struct-level Zeroize derive

**File:** `crates/scp-platform/src/testing/pre_rotation_custody.rs:35-39`

The `private_key: Zeroizing<[u8;32]>` field zeros on drop. But the struct itself is not `#[derive(Zeroize, ZeroizeOnDrop)]` — if a future field is added, it won't auto-zero. WASM's `PreRotationKeyEntry` does derive both. Match for defense-in-depth.

## Items Verified Sound

- `serde_hex_array::array64` / `array32` lowercase canonical hex with byte-count validation
- WASM and native zbase32 produce identical canonical encodings (alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`, MSB-first 5-bit packing, trailing-zero pad of fractional 5-bit group)
- Both native (`extract_public_key`) and WASM (`from_did`) reject 16 non-canonical zbase32 alternates that round-trip-decode to the same bytes via re-encode-and-compare
- `compute_pre_rotation_commitment` = SHA-256(public_key) consistent across native and WASM
- Migration signed digest: `SHA-256(DOMAIN || u32-BE len(old) || old || u32-BE len(new) || new || u64-BE rotated_at)` — domain-separated, length-prefixed, byte-identical native/WASM
- `WasmIdentity::fromDid` calls `ed25519_dalek::VerifyingKey::from_bytes` which rejects non-curve points (low-order points pass `from_bytes` but caught later by `verify_strict`)
- ADR-046 byte parity: `seed[0..32]=identity`, `[32..64]=active`, `[64..96]=pre-rotation`, `[96..128]=agent` ordering preserved
- Step 2c isolation test (`verify_migration_rejects_revealed_key_not_deriving_new_did`) is methodologically sound: re-signs migration_proof for attacker_new_did_B, pairs with legit pre_rot_proof
- Step 2b binding test (`verify_migration_rejects_commitment_mismatch_with_old_document`) — sound
- All 4 bridges have SHA-256(revealed_key) == commitment invariant assertion in their migrate tests
- Reverse-parity test uses 3 layered checks (Value-equality, native-deser round-trip, byte-canonicalize compare) — strong
- Production CSPRNG: `OsRng` across all software custody impls + CallbackKeyCustody
- Zeroization: `Zeroizing<[u8;32]>` propagation through migrate flow with explicit `drop()` on intermediate `SigningKey` copies; `revealed_private` zeros on drop after import
- `ScpIdentity::Debug` redacts all `KeyHandle` slot indices; prints public DID + pre_rotation_commitment (both public)
- `PreRotationKeyHandle` newtype isolation: no `From<KeyHandle>`, opaque inner u64
- 265/266 scp-identity lib tests pass (1 `#[ignore]`)

## Files

- `crates/scp-platform/src/traits.rs` — KeyCustody + PreRotationCustody traits
- `crates/scp-platform/src/testing/pre_rotation_custody.rs` — InMemoryPreRotationCustody
- `crates/scp-platform/src/testing/key_custody.rs` — InMemoryKeyCustody (generate_ephemeral, import_ed25519)
- `crates/scp-identity/src/dht.rs` — migrate_identity (1188+), verify_migration (1706+), extract_public_key (1903+)
- `crates/scp-identity/src/lib.rs` — ScpIdentity (manual Debug redact)
- `crates/scp-identity/src/document.rs` — serde_hex_array, MigrationProof, PreRotationProof, DidRotationEvent
- `crates/scp-ffi/wasm/src/identity.rs` — IdentityRecord, PRE_ROTATION_REGISTRY, migrate_inner, encode_rotation_event_json, from_did
- `crates/scp-ffi/uniffi/src/bridge.rs` — CallbackKeyCustody overrides, IdentityEntry
- `crates/scp-ffi/{src,napi}/src/identity.rs` — PyO3, NAPI bridges with cross-bridge SHA-256 invariant tests
