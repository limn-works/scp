---
name: SCP-1717 WASM rotate-key + cross-bridge migration review
description: Round-7 review findings for identity migration/rotation across scp-identity, file custody, WASM, Kotlin. Found 1 MEDIUM (docs example), no CRITICAL/HIGH.
type: project
---

# SCP-1717 / 1718 — Round-7 bug-catcher review

Branch: `worktree-scp-1717-wasm-rotate-key` at `ad92b17ee`

## Verdict: no CRITICAL/HIGH bugs in focus areas.

## Findings

- **MEDIUM**: `docs/examples/kotlin/Identity.kt:71` uses deprecated `advanced.migrate(identityHandle)` which the deprecation message says is protocol-incomplete (drops the `DidRotationEvent` required by spec §3.2.1 step 4b). The example will compile with a deprecation warning, but more critically it teaches users the wrong way to migrate. Fix: replace with `advanced.migrateWithRotationEvent(identityHandle)` and demonstrate forwarding `result.rotationEventJson` to active contexts (or explicitly discard with comment).

## Audited areas (clean)

### `crates/scp-platform/src/file.rs` — new `destroy_key` ordering
- Lookup-before-mutate pattern is sound: `read_file` + `atomic_write` precede map mutation. Read failure or write failure cannot orphan ciphertext on disk.
- Lock order `handle_map` → `file_write_lock` is consistent across `destroy_key`, `generate_keypair`, `import_ed25519_signing_key`, `append_entry`. No inversion.
- New `handle_map` → `pseudonym_keys` lock order is compatible with `sign`, `public_key`, `derive_pseudonym`, `derive_rotatable_pseudonym` — those drop `pseudonym_keys` BEFORE acquiring `handle_map`, so no concurrent two-lock hold by other paths.
- `removed_index < current_count` bounds check guards against malformed file emission. Implicitly proves `current_count > 0` so the `current_count - 1` subtract is safe.
- Pseudonym early-return at line 663 is correct — pseudonym handle IDs and disk-entry IDs come from the same `next_id` counter so they never collide.
- Test `destroy_key_rejects_out_of_bounds_entry_index` correctly exercises the desync rejection path.

### `crates/scp-identity/src/dht.rs` — `verify_migration` Step 0
- `bind_old_document_to_old_did` correctly handles missing `#0` VM (returns `MigrationVerificationFailed("old_document has no #0 verification method")`).
- Step ordering: Step 0 binding runs before signature reconstruction or window check, so a mismatched document is rejected early.
- `extract_public_key` is called first; if `old_did` is malformed, it returns `InvalidDidFormat` (not `MigrationVerificationFailed`). The test uses a valid `old_did`, so Step 0 reaches the VM lookup before failing.
- `verification_method_by_fragment("0")` correctly disambiguates `#0` from `#10`, `#00`, `#0a` via exact-suffix `ends_with("#0")`.

### `crates/scp-identity/src/dht.rs` — `migrate_identity` ordering
- Step 0 probe: `import_ed25519_signing_key` → `destroy_key` round-trip using OS-CSPRNG bytes (no collision risk with content-addressed custody).
- Steps 3-4 allocate new keys BEFORE Step 5's irreversible `destroy_after_migration`. Orphaned fresh keys on Step 5-8 failure are bounded and security-neutral (documented in inline comments).
- Step 7 publishes NEW doc BEFORE Step 8 republishes OLD with `alsoKnownAs`. Verifiers following `alsoKnownAs[new_did]` always find a real published target.
- Step 7b `destroy_old_operational_keys` correctly destroys `#active` and `#agent` but RETAINS `#0` (needed for Step 8 republish signing).
- Test `migrate_identity_destroys_old_active_key` verifies both invariants.

### `crates/scp-identity/src/document.rs` — `retire_operational_keys_for_migration`
- Exact-fragment match (not `ends_with("active")`) prevents future fragments like `#secondary-active` from being swept.
- `PreRotationCommitment` service is preserved (needed for `verify_migration` of subsequent verifications of the OLD doc).
- `#0` and `#retired-*` are preserved.

### `crates/scp-ffi/wasm/src/identity.rs` — `migrate_inner`
- Capacity pre-flight in Phase 2b runs BEFORE any mutation; mirrors `install_migrated_identity` Phase 1.
- Signature build + JSON encoding (fallible local ops) run BEFORE `pre_rotation_store` (registry mutation) — prevents orphaned new pre-rotation entry on encoding failure.
- WASM single-threaded model rules out concurrent registry mutations between phases.
- `pre_rotation_destroy_after_migration` correctly drops `PreRotationKeyEntry` (Zeroize on drop wipes private bytes).

### `crates/scp-ffi/wasm/src/identity.rs` — `from_did_inner`
- Capacity check uses split read+write borrows (defense-in-depth for hypothetical future re-entrant JS callback inside `or_insert_with`).
- Correctly preserves `Local` record's `agent_signing_key_bytes` and `custody_type` when from_did is called on a known-Local entry (no fresh-Resolved overwrite).

### `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Identity.kt` — RevocationStatus parsing
- Fail-closed when-block correctly rejects unknown JSON shapes including JsonNull, JsonArray, JsonPrimitive(non-"Active"), JsonObject(no "Revoked" key).
- `is JsonPrimitive` + content equality is the correct guard pattern (avoids `?.jsonObject` foot-gun).
- `revoked["revoked_at"]!!.jsonPrimitive.long` would throw NumberFormatException on a malformed Long, but Rust always serializes u64 as a JSON number that fits in Long for realistic timestamps.
- Rust's `revoked_by` field is ignored on the Kotlin side — model gap, not parsing bug (pre-existing model shape).

### Deprecation of `Identity.migrate(handle)`
- Only ONE production call site (in `docs/examples/kotlin/Identity.kt:71`) — see MEDIUM finding above. All other call sites are test-only with `@Suppress("DEPRECATION")`.

## Lessons saved
- `?.jsonObject` is unsafe for possibly-primitive values; use `is JsonObject` guard. Current Kotlin parser correctly avoids this.
- File-custody patterns: `lookup → file rewrite → map mutation` is the correct ordering to prevent orphaned ciphertext.
- WASM single-threading lets you skip locking but doesn't excuse skipping cap pre-flights when irreversible operations follow.
