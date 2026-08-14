---
name: c3c1-participation-record-review
description: Phase 2C-1 typed participation_record op (§7.3.2) FFI export review — COMPLETE on branch c3c-ts-work
metadata:
  type: project
---

# Phase 2C-1 — typed `participation_record` op (§7.3.2)

Reviewed UNCOMMITTED working-tree changes on branch `c3c-ts-work` (worktree
agent-a1400c1b005b502a3), HEAD `d1fec867b`. Verdict: **COMPLETE**.

**Why:** Phase 2C-1 exposes a typed participation/behavioral record over the FFI
as a typed result (SDKs RECEIVE it, never recompute). Scope = Rust core + 3
NATIVE bridges (PyO3/NAPI/UniFFI). WASM removed → native-only correct (ADR-034).
SDK wrappers = Phase 2C-2, GitHub issue #1943 (matrix cells false-with-exemption).

**How to apply:** if re-reviewing this op or 2C-2, the 11 canonical fields are:
subject_did, participation_duration_secs, governance_actions_against,
governance_actions_by, tool_invocation_count, tool_invocation_count_anchored,
context_creation_count, role_progression_count, attestation_count, computed_at,
event_log_root. All 11 cross each native bridge struct (verified 11/11 each).

## Key structural facts (load-bearing for future passes)
- Core: `ParticipationFacts` (scp-protocol trust/participation.rs) is the scalar
  projection; `From<&ParticipationRecord>` reuses the SAME `.len()`/`.values().sum()`
  reduction that `produce_participation_profile` was refactored to share → unsigned
  facts view and signed profile cannot drift. `tool_invocation_count_anchored:false`
  is SPEC-MANDATED (§7.3.2, line 247 "false until ADR-051"), NOT a placeholder.
- Runtime: `Supervisor::participation_record` gathers FULL unfiltered event log
  (governance_actions_against keys on projected target_did, so subject-filtered
  query would undercount) + Merkle root, delegates to core
  `compute_participation_record` with real `accessible_attestations` threaded IN
  (caller supplies, never `&[]` hardcoded). Empty log → core EmptyEventLog →
  ContextError (not silent empty record). `event_log_merkle_root` Result →
  `.unwrap_or([0u8;32])` is intentional (empty-log path), proven by test.
- Bridges source attestations via shared `verified_attestations` helper
  (scp-ffi/common/trust_store.rs) — factored from populate_and_aggregate, same
  AttestationCache/IdentityDidPublicKeyResolver/SystemClock wiring. NOT `&[]`.
- Enforcement: matrix Trust row 4 cells false + per-SDK exemptions citing #1943;
  bridge-aliases tri-bridge + wasm_required:false + wasm exemption (ADR-034);
  ffi-export-allowlist __repr__ dunder for PyParticipationRecord;
  pipeline_wiring 4 assertions (core compute + 3 bridges→Supervisor), ratchet
  MIN_ACTIVE_PIPELINE_ASSERTIONS 50→54 (additive, allowed).

## Verification run (all green) — re-confirmed 2nd independent pass
- check-sdk-coverage.py PASS (225 ops, 0 errors); check-bridge-symmetry.sh exit 0
  (0 findings); check-error-codes.sh exit 0 (2448 occurrences conform, VALID_7059 ok).
- participation_record_supervisor integration test 3/3; pipeline_wiring 83/83
  (incl. 4 new routing + ratchet floor-54 meta); bridge unit tests PyO3 4, NAPI 5,
  UniFFI 5 — all run+pass (not theater).
- CORRECTION (diff evolved since prior pass): VALID_7059 is now used by ALL THREE
  native bridges — PyO3 `participation_record_impl` (cached-attestations JSON
  parse failure → ScpPyError::ValidationError{code:VALID_7059}), NAPI
  `participation_record_on` (ScpNapiError::Validation), and UniFFI
  (ScpError::Validation). Live everywhere, not dead.
- CORRECTION (prior note was stale): a dedicated `ParticipationFacts::from` unit
  test DOES exist inside participation.rs —
  `participation_facts_flattens_record_collections_to_counts` at line 3052,
  asserts each scalar fact == the corresponding record-field reduction
  (duration=300, against=1, by=1, role=1, context_creation=1, anchored=false).
  Passes. Plus the runtime integration test + 3 bridge `*_view_exposes_all_facts`
  tests. Fully covered — no nicety gap.

## Lesson reinforced
- pipeline_wiring `fn_body_contains(SRC, fn_name, callee)` strips comments/strings
  then brace-matches the FIRST `fn <name>(` body → a `.participation_record(`
  match on the UniFFI method named `participation_record` is a genuine route
  (calls supervisor.participation_record), not theater. Still verify the call
  site by reading the diff — I did.
