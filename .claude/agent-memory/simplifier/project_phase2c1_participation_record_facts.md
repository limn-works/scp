---
name: phase2c1-participation-record-facts
description: Phase 2C-1 typed participation_record op — ParticipationFacts shared flattening + 4 pipeline assertions judged convergent (NOT BLOCKER); per-bridge record duplication is FFI-macro-inherent
metadata:
  type: project
---

Phase 2C-1 added a typed `participation_record` op (§7.3.2) across scp-core + 3 native bridges (PyO3/NAPI/UniFFI; WASM exempt per ADR-034, no Supervisor).

Reviewed the uncommitted change (branch c3c-ts-work). Verdict: appropriately simple, no BLOCKER.

**Why convergent / not over-engineered:**
- `ParticipationFacts` (`scp-protocol/src/trust/participation.rs`) is a GENUINE de-dup: `produce_participation_profile` previously inlined the `.len()`/`.values().sum()` reduction; now both it and the 3 bridges flatten through one `From<&ParticipationRecord>`. Collapses ~5 copies → 1.
- Per-bridge typed records (`PyParticipationRecord`/`NapiParticipationRecord`/`ParticipationRecordView`) are IRREDUCIBLE — `#[pyclass]`/`#[napi(object)]`/`uniffi::Record` are mutually exclusive macros; each `From` impl is a flat field copy. Same pattern as existing `NapiTrustScoreResult`.
- 4 pipeline_wiring assertions = exactly one per op×layer (closed, bounded wiring coverage, matches Integration-checklist #4). Ratchet 50→54 matches. This is convergent, NOT a denylist chasing spellings. **Do not flag this shape as BLOCKER.**
- `verified_attestations` helper in scp-ffi-common is a clean extraction of `populate_and_aggregate`'s attestation-sourcing half (same cache/resolver/clock wiring).

**Why:** This is the same convergence pattern as [[project_pr116_saga_ffi_export_pipeline_assertions]] — a typed FFI op fanned across bridges with one-per-seam pipeline assertions reads as "growth" but is bounded by the op count, not unbounded.

**How to apply:** When reviewing typed-FFI-op-across-bridges changes in this repo, per-bridge macro-record duplication and one-per-op×layer pipeline assertions are the expected baseline — not findings. Reserve BLOCKER for unbounded denylists / type-system-redundant gates.

Two residual non-blocking items flagged: (1) UniFFI pipeline assertion anchors on the non-unique fn name `participation_record` (first-match); robust today but fragile if a second same-named fn appears (PyO3/NAPI use unique inner-fn names `*_impl`/`*_on`). (2) `cached_attestations_json` defaults to "[]" on PyO3 but is required on NAPI/UniFFI — normalize when SDK wrappers land (#1943).
