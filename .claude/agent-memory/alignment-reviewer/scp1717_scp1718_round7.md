---
name: SCP-1717 + SCP-1718 Round-7 Review at HEAD 98d91dcb4
description: Fresh independent alignment review at HEAD 98d91dcb4 (30 commits ahead, 0 behind origin/main) — verdict ALIGNED with 1 informational doc drift
type: project
---

# SCP-1717 + SCP-1718 Round-7 Review at HEAD `98d91dcb4` (2026-05-10) — ALIGNED

Fresh independent assessment, no prior-round leakage. Branch at `98d91dcb4`, 30 commits ahead of origin/main, 0 behind. Round-6 commit `98d91dcb4` addressed round-5 review by adding the step-0 defense-in-depth `bind_old_document_to_old_did` check at top of `verify_migration` (extracted as helper at `crates/scp-identity/src/dht.rs:1907`), plus regression test `verify_migration_rejects_forged_old_document` (`:3913`), plus docstring corrections on `build_migration_proof` (`:1442`) and `verify_migration` (`:1936`) describing the length-prefixed digest, plus `hash-commitment-preimage-lifetime.md:41` doc drift correction (2-tuple → 3-tuple, "four" handles → three).

**Verdict: ALIGNED. 0 blocking, 0 material, 1 informational doc drift.**

## What verified

- **WASM rotate_active_key_inner** (`crates/scp-ffi/wasm/src/identity.rs:2136`): only touches `active_signing_key_bytes`, preserves `pre_rotation_handle`, `#0`, agent state. Test `rotate_key_preserves_pre_rotation_commitment` (`:5086`) pins behavior.
- **Pre-rotation chain across 4 bridges**: SHA-256(revealed_key) == commitment computed byte-identically (native dht.rs `:1287`; WASM `:2782-2791`; PyO3 `crates/scp-ffi/src/identity.rs:1336`; NAPI `crates/scp-ffi/napi/src/identity.rs:301`; UniFFI `crates/scp-ffi/uniffi/src/bridge.rs:12817`).
- **Reverse-direction JSON parity** (`crates/scp-ffi/wasm/src/identity.rs:5651` Some-arm; `:5733` None-arm): pinned both arms with canonical-sort-keys byte-canonicalisation check.
- **PreRotationCustody trait** (`crates/scp-platform/src/traits.rs:718`): distinct `PreRotationKeyHandle` (`:80`) with no From/Into either direction → type-level §9.7.4.1 §3 isolation.
- **verify_migration invariants**: 6 always-checked (sig, self-cert old_did, future skew, past window, epoch floor, STRONG-when-committed) + 3 conditional STRONG-assurance (SHA-256 commitment, commitment binds OLD doc service, revealed_key self-certs new_did). NEW step-0 `bind_old_document_to_old_did` runs BEFORE any other invariant.
- **migrate_identity step ordering** (`crates/scp-identity/src/dht.rs:1217-1439`): step-0 OS-CSPRNG probe pre-flight, step-1 reveal, step-2 build proofs, step-3 new pre-rotation seed, step-4 store new pre-rotation, step-5 destroy old + import private as new #0, step-6 build new doc + ScpIdentity, step-7 publish NEW first, step-7b destroy old #active+#agent (`destroy_old_operational_keys` at `:1872`), step-8 republish OLD with `alsoKnownAs` + `retire_operational_keys_for_migration` (defense-in-depth).
- **FileKeyCustody generate_keypair lock-ordering parity** (`crates/scp-platform/src/file.rs:567`): handle_map.lock().await held BEFORE append_entry, mirroring import_ed25519_signing_key (`:887`). Regression test `generate_keypair_concurrent_destroy_does_not_corrupt_handle_map` (`:1372`).
- **decode_multibase_key curve-point validation** (`crates/scp-identity/src/dht.rs:1608`): VerifyingKey::from_bytes gate. Regression test `decode_multibase_key_rejects_non_curve_point` (`:2822`).
- **WASM from_did guards** (`crates/scp-ffi/wasm/src/identity.rs:2171`): canonicality (`:2199`), curve-point (`:2214`), capacity (`:2240`), Local-record preservation (`:2267-2290` — uses `or_insert_with` to NOT overwrite Local; reads back custody_type, has_agent_key, agent_public_key_multibase from existing record). Tests at `:5276`, `:5336`, `:5394`, `:5446`.
- **Kotlin IdentityMigrateResult + migrateWithRotationEvent** (`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Identity.kt`): `identityRotationEventJson` shim (`:100`), `migrate` convenience (`:290`) returning Long, `migrateWithRotationEvent` (`:311`) returning result struct, `IdentityMigrateResult` data class (`:476`).
- **CI clippy**: PASSES with full CI feature combo (scp-ffi-uniffi/allow_in_memory_custody, scp-ffi/allow_in_memory_custody, scp-ffi-napi/allow_in_memory_custody, scp-core/testing, scp-runtime/testing).
- **Lesson doc drift** (`hash-commitment-preimage-lifetime.md:41`): correctly says 3-tuple `(ScpIdentity, DidDocument, PreRotationKeyHandle)` and three operational handles (identity_key, active_signing_key, agent_signing_key). Round-5 drift closed.
- **Migration-digest docstrings** (`crates/scp-identity/src/dht.rs:1442` and `:1936`): correctly describe `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did || u32_be(len(new_did)) || new_did || u64_be(rotated_at))`. Round-5 drift closed.

## Informational finding (NOT blocking)

**CHANGELOG.md:64** — wording drift: `... Kotlin, surfaced through the IdentityMigrateResult returned by IdentityAdvancedBridge.migrate`. The actual `IdentityAdvancedBridge.migrate` (Identity.kt:290) returns `Long`; `IdentityMigrateResult` is returned by `migrateWithRotationEvent` (Identity.kt:311). Single-word fix.

## Reusable patterns

1. **Round-by-round verification cycle works**: round-1-through-round-6 have each closed prior-round informational findings. The pattern of explicitly enumerating prior-round drift in the next prompt is what made the doc fixes land. Without explicit carry-forward enumeration, doc-comment drift survives indefinitely (the round-4 + round-5 reviews both observed the lesson drift; only round-6 fixed it because the carry-forward was explicit).
2. **Reverse-direction parity tests are necessary AND must cover all Option arms**: round-3 added Some arm, round-3/4 added None arm. Without the None-arm test, a future `#[serde(skip_serializing_if = "Option::is_none")]` on either side would pass silently.
3. **`or_insert_with` is the right pattern for "preserve-if-present" semantics**: WASM from_did at `:2257-2290` correctly uses entry/or_insert_with to fall through to the existing record's Local fields rather than overwriting. Reads custody_type and agent_signing_key_bytes from the existing record after the entry-API call, rather than hardcoding them.
4. **Step-0 defense-in-depth before any other invariant**: `bind_old_document_to_old_did` runs FIRST so a forged document's `pre_rotation_service()` can't influence downstream STRONG-when-committed enforcement. Pattern reusable for any verification function that consults caller-supplied auxiliary data.
