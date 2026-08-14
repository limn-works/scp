---
name: c3c-scp302-303-trust-sdk-review
description: SCP-302 (ADR-057 ucan_evaluate/CapabilityValidation) + SCP-303 (§7.3.2 participation_record) four-SDK rebuild — COMPLETE verdict, worktree agent-a1400c1b005b502a3 @7e0f22894
metadata:
  type: project
---

# C3c trust-SDK rebuild (SCP-302 + SCP-303) — COMPLETE

**GAP CLOSED @1a5394cee (2026-07-02).** The `.pyi` stub gap flagged in the @9d32bb297 narrow
re-verify (participation_record + economy_verify_payment_receipts absent from `_scp_core.pyi`)
is now fixed by ONE commit `1a5394cee` (7 insertions, `.pyi`-only). Full pyo3-vs-stub audit at
HEAD 1a5394cee: only new `pyo3(name)` = participation_record (stubbed, 3-param last-defaulted);
only added `pub fn`s = participation_record + ucan_evaluate (both stubbed); only signature
changes = ucan_evaluate (capability &str→Option, stub has `capability=...` ✓) +
verify_participation_requirements (gained `expected_subject` first arg; module-level free-fn
stub `(expected_subject, requirements_json, profile_json)->None` matches). economy_verify was a
pre-existing stub gap (method identical on origin/main), now added `(self, receipts_json)`.
validate-prd 369 exit 0; check-sdk-coverage 0 errors exit 0. **Verdict now COMPLETE (full).**
Remaining items all pre-tracked (do NOT re-raise): #1988 check_capability_requirements unwired,
#1990 .pyi parity gate, #1991 typed-vs-JSON input, #1992/#1993/#1994.

Worktree `agent-a1400c1b005b502a3`, branch `c3c-ts-work` @7e0f22894 (trust feature; NOT the
`ceiling`/reconcile_to_ceiling branch on the main tree). WASM removed per ADR-055 → 3 bridges
(PyO3/NAPI/UniFFI), 4 SDKs at parity.

**Verdict: COMPLETE.** Every SCP-302 + SCP-303 acceptance criterion met end-to-end. Both gates
exit 0: `validate-prd.py` (369 stories), `check-sdk-coverage.py` (226 ops, 0 errors, 1 benign
kotlin addRelay tree-sitter exemption). 76 core participation tests + pipeline_wiring + conformance green.

Traced facts (verify, don't re-derive):
- **ucan_evaluate**: core `evaluate_ucan` takes `Option<&CapabilityUri>` (diagnostic); `validate_ucan`
  keeps mandatory `&CapabilityUri` (gate). All 3 bridges take optional capability + coerce empty→None
  via `.filter(|c| !c.trim().is_empty())`. All 3 fail-closed on empty `presenting_agent_did` (audience
  binding). Pipeline asserts `{pyo3,napi,uniffi}_ucan_evaluate_routes_to_core_evaluate_ucan`.
- **participation_record**: `Supervisor::participation_record(ctx, subject, accessible_attestations)`
  → core `compute_participation_record` over FULL unfiltered log + real Merkle root (fail-closed on
  root; zero-root only for empty log). 12 fields incl. `tool_invocation_count_anchored` +
  `attestation_count_anchored` (both const-false, legit) at core `ParticipationFacts` + all 3 bridge
  views (Py/Napi/UniFFI) + all 4 SDK `BehavioralRecord`. Pipeline asserts routes-to-supervisor ×3
  (UniFFI one guards self-satisfying name-match by pinning BOTH `supervisor` + `.participation_record(`).
- **evaluate_trust / evaluateTrust**: all 4 SDKs; Layer-1 AND-combines 6 booleans, passes subjectDid
  as presenting_agent_did; Layer-2 RECEIVES core record (no client-side event_log_query/classification —
  Py grep 0, TS `eventLogQuery` in evaluateTrust body is a COMMENT only, real method separate);
  empty-log CTX_2076 folded to zeroed record branching on STRUCTURED code. Python args `(scp, context_id,
  subject_did, capability_tokens)`.
- **CTX_2076** `SCP-CTX-2076` defined once (error_codes.rs), mapped in all 3 bridges from
  `ContextError::NoParticipationFacts`, consumed in all 4 SDKs.
- **verify_participation_requirements**: required `expected_subject` (2nd positional) threaded core→3
  bridges→4 SDKs (Swift = UniFFI-generated free fn, no SCP-class method). Insecure 2-arg twins DELETED
  (commit e00846c92); no old-signature caller. Core tests: `verify_rejects_cross_subject_profile_replay`
  (negative), `verify_rejects_empty_expected_subject`, `verify_subject_owned_profile_satisfies_requirement`
  (positive), `verify_mixed_subjects_counts_only_matching_subject`. check-sdk-coverage matches the secure
  symbol in all 4.
- **RoleAssigned/MemberJoined/MemberLeft projected subject_did** (AC3): `compute_tracks_role_history`
  proves RoleAssigned actored by admin but subject alice counts for alice not admin.
- **CachedAttestation typed input**: all 4 participation_record wrappers take typed list → JSON → bridge;
  bridges source verified attestations from own ProtocolRepository trust store (ProtocolRepositoryTrustBridge
  + populate_and_aggregate); evaluate_trust passes empty set (attestation_count==0, tested real-FFI/real-napi).
- **matrix**: UCAN.evaluate + Trust.participation_record + Trust.evaluate_trust + Bridge.{evaluate_trust,
  register} + Identity.{add_agent_key,rotate_agent_key,remove_agent_key,migrate} + Discovery.discover +
  Economy.verify_payment_receipts all 4 SDKs true, exemptions removed. Identity.rotate_key: ts flipped
  true (exemption removed); kotlin/swift stay false w/ PRE-EXISTING exemptions (AC only required ts).
- **No stale "eleven"** anywhere; **no phantom-deferral residue** for C3c cells (remaining matrix
  "follow-up" notes are unrelated pre-existing entries: Identity.migrate MigrationPartialState, context_join
  spending_ucan, standing_context contact-graph).
- Prose apparatus fully deleted from Python trust.py (all 9 symbols grep 0); obsolete fields removed
  (Py contexts_participated/total_duration/tool_invocations/role_history/endorsement_accuracy;
  TS toolInvocations/participationCount/participationDurationSeconds). TS error typing via single
  `mapBridgeError` keyed on `[SCP-CAT-NNNN]` code, passes typed errors through untouched; no `.message`
  prose-branching.

OBSERVATION (non-blocking, out of story scope): Identity.rotate_key kotlin/swift exemptions cite
"UniFFI exports it; no wrapper yet" without an ADR/§/SCP reference, and are inconsistent with the sibling
Identity agent-key ops which ARE all-true. Pre-existing; SCP-302 AC only required ts=true.

## Parallel-review cross-check (simplifier + chronicler + api-design)
- simplifier: CLEAN — twin deletion clean, no orphaned dead types; empty-subject core guard vs bridge
  validate_did are distinct layers not redundant; challenge canonicalization propagation is a real fix.
- chronicler: CLEAN — no stale refs/drift/phantom-deferral; attestation_count_anchored NOT on signed
  ParticipationProfile (only unsigned facts/BehavioralRecord), matches §7.3.2.1:260; §25 KAT lockstep
  (root 0x0c6f…4117, event_count 9); validate-prd 369 stories.
- api-design: NEEDS REVISION (API-quality, NOT completeness). Two findings, both verified accurate,
  NEITHER flips COMPLETE:
  1. Swift Trust.swift:5 header doc lists ucanEvaluate(...presentingAgentDid:capability:...) — the
     WRAPPER order — but the block claims to document the GENERATED export, whose order is
     capability BEFORE presentingAgentDid (ScpBindings.swift:3285; bridge.rs:13931). Cosmetic
     doc-vs-code inaccuracy; not a spec/ADR/PRD divergence, no AC covers doc param order.
  2. verify_participation_requirements "vestigial bool": UniFFI/NAPI bridges return Result<bool> with
     unconditional Ok(true) (bridge.rs:6398, napi trust.rs:312); Python returns None+raises. IMPORTANT
     completionist distinction I verified: core `verify_participation_requirements` returns
     `Result<(), ParticipationAdmissionError>` — UNIT, not bool. `Ok(())` success / `Err` on every
     failure (empty-subject, bad-sig, stale, threshold-not-met, insufficient-signers). There is NO
     `false` to drop → bridge-invented always-true bool (API misuse-resistance issue), NOT a
     dropped-signal correctness bug. Preferred fix: align UniFFI/NAPI to Python's void+throw contract.
     LESSON: a bridge Result<bool> over a core unit-returning Result<(),E> enforcement fn is
     vestigial-by-construction, never a dropped signal — check the CORE return type before escalating
     an "always-true bool" as a correctness bug.
