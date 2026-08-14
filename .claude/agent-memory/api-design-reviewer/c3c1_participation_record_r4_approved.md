---
name: c3c1-participation-record-r4-approved
description: C3C-1 typed participation_record op R4 — APPROVED; supervisor-acquire divergence dispositioned to issue #1944 (not per-op patch), confirmed sound
metadata:
  type: project
---

C3C-1 typed `participation_record` op (branch c3c-ts-work, uncommitted) — R4 APPROVED, double-zero candidate. Supersedes the R1/R2/R3 NEEDS REVISION rounds: all earlier fixes have LANDED.

**Why:** Final round on the 3-native-bridge (PyO3/NAPI/UniFFI; WASM removed; SDK wrappers = #1943) typed participation-record op. R3 had flagged a SECOND supervisor-fail-mode divergence; that whole class is now explicitly dispositioned, not patched.

**How to apply:**
- The supervisor-ACQUISITION divergence (PyO3 not-attached/suspended → `supervisor(bi)?` runtime.rs:166 → `ScpPyError::context()` error.rs:199 → CTX_2001 catch-all, pinned by `generic_context_error_keeps_ctx_2001` error.rs:876; vs NAPI runtime.rs:806 helper CTX_2000 ×2 branches; vs UniFFI inline CTX_2000 ×2) is CORRECTLY left alone and filed as cross-bridge convention issue **#1944**. It is pre-existing, lives in the shared per-bridge supervisor helpers, affects ALL supervisor-acquiring ops, and PyO3's CTX_2001 is a documented catch-all asserted by Python tests. Per-op patching would trade a cross-bridge inconsistency for an intra-bridge one + break tests. Filing #1944 = the convergent fix.
- The op's OWN compute-failure path IS converged: PyO3 explicit `ScpPyError::ContextError{code:CTX_2000}` with comment; NAPI/UniFFI CTX_2000. JSON-parse + attestation-source paths = VALID_7059 ×3.
- 11-field parity across all 4 structs (core ParticipationFacts + Py/Napi/View) verified field-by-field; NAPI i64-widen documented; event_log_root hex-string ×3 bridges. Attestation sourcing converged via shared `trust_store::verified_attestations`. 4 new pipeline_wiring assertions (ratchet 50→54), UniFFI self-mention trap defended. Matrix false×4 + #1943 exemptions, bridge-aliases wasm:[]/wasm_required:false ADR-034.
- Sole carried SUGGESTION (for #1943): 3 divergent dev-facing names (ParticipationRecord/NapiParticipationRecord/ParticipationRecordView) — unify at SDK-wrapper layer.

**LESSON:** when a per-bridge error-code divergence is a SHARED-HELPER convention affecting a whole op class (not the reviewed op's own body), the right call is a cross-bridge convention issue, NOT special-casing one op — special-casing creates an intra-bridge inconsistency that's worse. Verify the premise by reading the helper + the test that pins the catch-all before accepting the disposition.

See [[c3c1_participation_record_supervisor_unavailable_divergence]] (R3) and [[c3c_participation_record_op]] (original APPROVED).
