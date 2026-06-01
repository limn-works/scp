---
name: SCP-1717 + SCP-1718 Round-7 Alignment Review at HEAD ad92b17ee (2026-05-10)
description: ALIGNED verdict. Round-7 commit ad92b17ee addressed all round-6 informational drifts (Kotlin migrate deprecation, doc-precision in rustdoc/ADR/CHANGELOG, FileKeyCustody destroy_key hardening). All 4 bridges keep byte-parity. Clippy clean. 3 small informational findings (verify_migration rustdoc Step 0 enumeration; ADR §4c MODERATE bullet wording; CHANGELOG fail-closed Kotlin bullet missing).
type: project
---

## Branch / HEAD
- Branch: `worktree-scp-1717-wasm-rotate-key`
- HEAD: `ad92b17ee` (round-7 fixes), parent `98d91dcb4` (round-6 fixes)
- Round-7 commit message lists 11 promised fixes; all 11 land.

## What round-7 changed (vs. round-6 at 98d91dcb4)
1. `bind_old_document_to_old_did` rustdoc (`dht.rs:1907-1918`) — rewritten to describe self-cert-only scope; dropped the misleading "omits PreRotationCommitment" attacker example.
2. `verify_migration` rustdoc (`dht.rs:2013-2028`) — added `# Caller contract` requiring `old_document` from a verified resolution path (`resolve_did`, `verify_and_deserialize`, `relay_resolve`).
3. `MigrationProof`/`PreRotationProof` doc-comments (`document.rs:1167-1196`) — switched to `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did || u32_be(len(new_did)) || new_did || u64_be(rotated_at))`.
4. ADR-003 §4c (`phase-1.md:402-419`) — renumbered to 1-10. Invariant 1 is now Step 0 self-cert binding; 2-7 are remaining always-checked; 8-10 are conditional-on-Some.
5. `build_migration_proof` rustdoc (`dht.rs:1441-1460`) — added digest-scope note PLUS explicit defense-in-depth caveat: future `PreRotationProof` fields are NOT auto-covered by the migration signature and MUST be wired into either the digest input or a dedicated `verify_migration` invariant.
6. `FileKeyCustody::destroy_key` (`file.rs:644-741`) — standardized lock order (`handle_map` first, then `pseudonym_keys`); defers in-memory map mutation until `atomic_write` succeeds; validates `removed_index < current_count` and returns typed `CustodyError` on desync.
7. New regression test `destroy_key_rejects_out_of_bounds_entry_index` (`file.rs:1134`).
8. New regression test `verify_migration_rejects_old_document_without_vm0` (`dht.rs:4004`).
9. Kotlin `IdentityAdvancedBridge.migrate(handle)` — `@Deprecated(WARNING, ReplaceWith("migrateWithRotationEvent(identityHandle)"))` at `Identity.kt:299-308`. In-tree caller in `IdentityAdvancedBridgeTest.kt` gets `@Suppress("DEPRECATION")`.
10. Kotlin `IdentityAttestation.fromJsonObject` (`Identity.kt:576-603`) — fails closed with `IllegalArgumentException` on unrecognized `revocation_status` JSON shapes; two new tests cover primitive + object unknown-shape branches.
11. CHANGELOG line 64 — Kotlin SDK rotation-event bullet now correctly attributes `IdentityMigrateResult` to `migrateWithRotationEvent` (not `migrate`).

## What's preserved from prior rounds
- All 4 bridges (PyO3, NAPI, UniFFI, WASM) ship `SHA-256(revealed_key) == commitment` byte-parity assertion (`crates/scp-ffi/src/identity.rs:2179`, `napi/src/identity.rs:1540`, `uniffi/src/bridge.rs:15408`, `wasm/src/identity.rs:5187`).
- WASM `identity_rotate_key` is in-place active-key replacement only (`wasm/src/identity.rs:2127`); does not touch `#0`, DID, or pre_rotation state.
- `verify_migration` 7 always-checked + 3 conditional invariants; Step 0 (`bind_old_document_to_old_did`) runs FIRST at `dht.rs:2043` before any downstream invariant consults `old_document.pre_rotation_service`.
- Hard epoch floor `MIGRATION_EPOCH_FLOOR_UNIX_SECS = 1_700_000_000`, future skew 5min (`MAX_FUTURE_SKEW_SECS`), past window 5yr (`MAX_PAST_WINDOW_SECS`).
- `ScpIdentity` has exactly 3 operational handles (`identity_key`, `active_signing_key`, `agent_signing_key`) + `pre_rotation_commitment: [u8; 32]` + `did: String`. Lesson `hash-commitment-preimage-lifetime.md:41` correctly says 3-tuple and 3 op handles.
- Reverse-direction JSON parity tests cover Some + None arms.
- `cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-ffi/allow_in_memory_custody,scp-ffi-napi/allow_in_memory_custody,scp-core/testing,scp-runtime/testing -- -D warnings` clean.

## Three informational findings (non-blocking, doc-precision only)
1. `dht.rs:1947-1965` — `verify_migration` rustdoc `# Verification Steps` enumerates only `1. Migration proof` and `2. Pre-rotation proof`; does NOT explicitly list Step 0 (`bind_old_document_to_old_did`) as a numbered preconditional step in the user-facing summary. The `# Errors` and `# Caller contract` sections cover it, but the step-list could mislead docs-only readers. Fix: prepend "0. Document binding (preconditional)" so the rustdoc step-list parity-matches ADR-003 §4c's 1-10 numbering.
2. `.docs/adrs/phase-1.md:418` (Assurance levels — MODERATE bullet) — reads "invariants 1-6 enforced, plus the `new_did` self-cert"; slightly misleading because invariant 7 (STRONG-presence enforcement) is always-checked and just passes vacuously when the OLD doc has no commitment service. Fix: change to "invariants 1-7 enforced (invariant 7 passes vacuously because the OLD document has no `PreRotationCommitment` service to enforce)".
3. `CHANGELOG.md` — no entry covering Kotlin `IdentityAttestation.fromJsonObject` fail-closed behavior change. `internal companion object` makes `fromJsonObject` non-public, but the thrown `IllegalArgumentException` propagates upward through `linkAttestations` etc. when a Rust-side enum is widened. Fix: add one-line bullet under "Pre-rotation custody isolation + DID migration wiring" noting the fail-closed behavior shift.

## Reusable patterns for future rounds
- **Doc-step-list vs. ADR-invariant-numbering drift.** Whenever an ADR enumerates N invariants, the corresponding rustdoc step-list should parity-match the numbering — readers consult both, and a numbering mismatch creates confusion about what "Step 0" or "invariant 7" refers to.
- **MODERATE vs. STRONG bullet wording.** When an invariant is always-checked but passes vacuously on one branch (e.g., invariant 7 here), the assurance-level summary should still cite it under "1-N enforced (invariant N passes vacuously because ...)" rather than "1-(N-1) enforced", so reviewers don't misread it as conditional.
- **CHANGELOG fail-closed parsing changes.** When a parser changes from defaulting-to-`X` to throwing on unrecognized variants, log it in CHANGELOG even if the parser is `internal` — the exception still propagates through public surface (`linkAttestations`, etc.) when Rust adds a new enum variant.
- **Final-round commit pattern.** Round-7 was 100% doc-precision, lock-discipline, regression tests, and deprecation hygiene — no new protocol surface. Recognize this shape as "settling round, merge after one more clean review."
