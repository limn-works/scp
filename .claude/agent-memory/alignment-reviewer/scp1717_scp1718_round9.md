---
name: SCP-1717 + SCP-1718 Round-8 Alignment Review at HEAD 6aa83a96d (2026-05-03)
description: ALIGNED. Round-8 commit 6aa83a96d (single commit since round-7 ad92b17ee, +105/-14 LOC across 4 files) addressed all 4 round-7 promised follow-ups: Kotlin migrate(handle) bumped to DeprecationLevel.ERROR, example file uses migrateWithRotationEvent, bind_old_document_to_old_did wraps extract_public_key + decode_multibase_key errors in uniform MigrationVerificationFailed, Step 0 mismatch error includes 12-byte hex prefixes of did-derived vs document-derived pubkeys. Regression test verify_migration_rejects_old_document_with_malformed_vm0_multibase locks the InvalidDidFormat→MigrationVerificationFailed uniformity. Test assertion verifies hex-prefixed operability hint. Kotlin IdentityAdvancedBridgeTest @Suppress bumped from DEPRECATION to DEPRECATION_ERROR. All 4 bridges (PyO3, NAPI, UniFFI, WASM) ship SHA-256(revealed_key)==commitment byte-parity. Clippy clean (full CI feature combo). 0 blocking, 0 material, 3 informational doc-precision drifts CARRIED FORWARD from round-7 (round-8's touch-set didn't include them).
type: project
---

## Branch / HEAD
- Branch: `worktree-scp-1717-wasm-rotate-key`
- HEAD: `6aa83a96d` (round-8 fixes), parent `ad92b17ee` (round-7 fixes)
- Round-8 diff: 4 files, +115/-14 LOC (105 net additions, mostly the new regression test)
- 1 commit advance from round-7

## Round-8 Promised Fixes (4 items, all landed)
1. **Kotlin `migrate(handle)` `DeprecationLevel.ERROR`** — bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Identity.kt:306 — bumped from `DeprecationLevel.WARNING` (round-7) to `.ERROR` (round-8). Compile-time blocker, not just warning. Kotlin test `@Suppress` updated `DEPRECATION` → `DEPRECATION_ERROR` accordingly. ✓
2. **Example file uses `migrateWithRotationEvent`** — docs/examples/kotlin/Identity.kt:70-77 — replaces `advanced.migrate(identityHandle)` with `advanced.migrateWithRotationEvent(identityHandle)`, prints `migrated.handle`, comment explicitly tells caller to forward `migrated.rotationEventJson` to each active context. Required because the deprecated overload now ERRORs at compile time. ✓
3. **Uniform `MigrationVerificationFailed` error surface in `bind_old_document_to_old_did`** — crates/scp-identity/src/dht.rs:1919-1948. Round-7 had `extract_public_key(old_did)?` and `decode_multibase_key(&old_doc_vm0.public_key_multibase)?` bubbling raw `IdentityError::InvalidDidFormat`. Round-8 wraps both in `.map_err(|e| IdentityError::MigrationVerificationFailed(format!("..: {e}")))`. Matches the `verify_migration` rustdoc's `# Errors` promise that Step 0 failures uniformly surface as `MigrationVerificationFailed`. ✓
4. **Step 0 mismatch error includes 12-byte hex prefixes** — crates/scp-identity/src/dht.rs:1939-1945. Round-7 message was `"old_document does not derive old_did"` (no operability hint). Round-8 expands to `"old_document #0 verification method does not derive old_did (did-derived: {12-hex}..., document-derived: {12-hex}...)"`. Tests at dht.rs:4001-4006 lock both the substring and the hex-prefixed operability hint. ✓

## Round-8 Regression Test (new, +82 LOC)
- `verify_migration_rejects_old_document_with_malformed_vm0_multibase` (dht.rs:4087-4153). Forges a document whose `id` matches the legitimate `old_did` but whose `#0` `publicKeyMultibase` is `"not-a-multibase-encoded-key"` (missing `z` prefix that `decode_multibase_key` requires). Asserts: (1) `verify_migration` returns `Err(MigrationVerificationFailed(_))`, NOT a different `IdentityError` variant; (2) error message contains `"malformed publicKeyMultibase"`. Closes the silent `InvalidDidFormat` leak that round-7 didn't catch.

## Bridges + Behavioral Parity
- **All 4 bridges (PyO3, NAPI, UniFFI, WASM)** still ship the `SHA-256(revealed_key) == pre_rot.commitment` byte-parity assertion in their bridge-local test suites:
  - PyO3: crates/scp-ffi/src/identity.rs:2178-2183
  - NAPI: crates/scp-ffi/napi/src/identity.rs:1538-1543
  - UniFFI: crates/scp-ffi/uniffi/src/bridge.rs:15405-15411
  - WASM: crates/scp-ffi/wasm/src/identity.rs (parity check via `encode_rotation_event_json` round-trip)
- Reverse-direction JSON parity (native serde ↔ WASM `encode_rotation_event_json`) test still in place from round-2.
- Migration digest format (native + WASM): `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did || u32_be(len(new_did)) || new_did || u64_be(rotated_at))` — byte-identical (native dht.rs:1467-1480, WASM identity.rs:2615-2637).

## verify_migration Invariants (10 total, ADR-003 §4c)
- Always-checked (1-7, MODERATE assurance):
  1. Step 0 self-cert binding of `old_document` to `old_did`
  2. Migration proof signature (Ed25519 `verify_strict`)
  3. Self-cert binding of `migration_proof.old_public_key` to `old_did`
  4. `rotated_at` future-skew bound (5 min saturating)
  5. `rotated_at` past-window bound (5 years saturating)
  6. Hard epoch floor (`MIGRATION_EPOCH_FLOOR_UNIX_SECS = 1_700_000_000`)
  7. STRONG-presence enforcement (`pre_rotation_proof.is_some() || old_document.pre_rotation_service().is_none()`)
- Conditional (8-10, applied only with `Some(_)`):
  8. `SHA-256(revealed_key) == commitment`
  9. `commitment` matches old doc's `PreRotationCommitment` service entry
  10. `revealed_key` self-certifies to `new_did`

## Findings (3 informational, all CARRIED FORWARD from round-7)

### F-9.1 (informational, doc-precision): `verify_migration` rustdoc `# Verification Steps` enumeration omits Step 0, Step 1b, Step 1c
- **File:** crates/scp-identity/src/dht.rs:1955-1976
- **Issue:** The `# Verification Steps` block enumerates only `1. Migration proof (MODERATE assurance)` and `2. Pre-rotation proof (STRONG assurance, optional)`. The implementation also runs Step 0 (`bind_old_document_to_old_did` at line 2053, before all other invariants), Step 1b (`old_public_key` → `old_did` self-cert at lines 2096-2117), Step 1c (STRONG-presence enforcement at lines 2119-2141). All three are documented in the `# Errors` section (lines 2003-2021) and the `# Caller contract` section (2023-2037), but a reader of `# Verification Steps` alone would not learn that Step 0 binds the document or that Step 1b binds the signer.
- **Severity:** Informational. The behavior is correct; only the in-source rustdoc is incomplete vs. the 10-invariant ADR enumeration.
- **Fix recommendation:** Renumber `# Verification Steps` to mirror ADR §4c's 10 invariants. Suggested split: `0. Document self-cert (always checked)`, `1. Migration proof signature (always checked)`, `1b. Signer self-cert (always checked)`, `1c. STRONG-presence enforcement (always checked when OLD doc commits)`, `2. Pre-rotation proof (conditional: 2a, 2b, 2c)`. Approx 12-15 line addition to the existing rustdoc block.

### F-9.2 (informational, doc-precision): ADR-003 §4c MODERATE bullet says "invariants 1-6 enforced" but invariant 7 is also always-checked
- **File:** .docs/adrs/phase-1.md:418
- **Issue:** The ADR text reads: `"With pre_rotation_proof = None AND the OLD document has no PreRotationCommitment service: invariants 1-6 enforced, plus the new_did self-cert..."`. This wording implies invariant 7 is skipped on this path. In reality, invariant 7 (STRONG-presence enforcement) is ALWAYS evaluated; it just passes vacuously when both `pre_rotation_proof.is_none()` AND `old_document.pre_rotation_service().is_none()`. CHANGELOG.md line 62 has the correct framing ("(1-7) MODERATE assurance, conditional (8-10) STRONG assurance"). The ADR drift is purely textual.
- **Severity:** Informational. No code-level impact; just narrative inconsistency.
- **Fix recommendation:** Change `"invariants 1-6 enforced"` → `"invariants 1-7 enforced (invariant 7 passes vacuously when no service is committed)"`. ~10-word edit.

### F-9.3 (informational, doc-precision): CHANGELOG missing one-line bullet for Kotlin `IdentityAttestation.fromJsonObject` fail-closed behavior change
- **File:** CHANGELOG.md (Unreleased / Pre-rotation custody isolation block)
- **Issue:** Round-7 added the `IdentityAttestation.fromJsonObject` fail-closed parser (bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Identity.kt:576-603) — unrecognized `revocation_status` JSON shapes now throw `IllegalArgumentException` instead of defaulting to `RevocationStatus.Active`. This is a behavior change visible to SDK consumers (a Rust enum variant addition would now surface as a Kotlin parse failure rather than silent mis-categorization as Active). CHANGELOG has no entry describing this. Round-8 also didn't touch CHANGELOG.
- **Severity:** Informational. Cosmetic / release-notes-completeness; not a protocol-correctness issue.
- **Fix recommendation:** Add one-line bullet near the existing Kotlin-related items: `- **Kotlin** \`IdentityAttestation.fromJsonObject\` now fails closed on unrecognized \`revocation_status\` JSON shapes (throws \`IllegalArgumentException\` instead of defaulting to \`RevocationStatus.Active\`). A future Rust enum variant addition will surface as a parse error rather than a silent fail-open default.`

## Verdict
ALIGNED. 0 blocking, 0 material. 3 informational doc-precision drifts (all carried forward from round-7; round-8's touch-set didn't include the affected files: dht.rs rustdoc, phase-1.md §4c MODERATE bullet, CHANGELOG Kotlin bullet). The round-8 commit cleanly addressed all 4 round-7 promised follow-ups, added one regression test, kept clippy + all bridge invariant parity intact.

## Reusable Pattern (from this round)
When a deprecation level is raised from WARNING → ERROR in Kotlin, the test suite's `@Suppress` annotation MUST also bump from `DEPRECATION` → `DEPRECATION_ERROR` — plain `DEPRECATION` only covers `DeprecationLevel.WARNING`. Forgetting this surfaces as `unresolved reference: migrate` or `Cannot access 'migrate': it is private in 'IdentityAdvancedBridge'`-style compile errors in tests because the compiler rejects calls to ERROR-deprecated symbols even with @Suppress("DEPRECATION"). Round-8 caught this in the same commit as the level change.
