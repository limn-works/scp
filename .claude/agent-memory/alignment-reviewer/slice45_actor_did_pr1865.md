---
name: slice45-actor-did-pr1865
description: PR #1865 slices 4+5 (event-log actor_did convergence) alignment review at d7216140b — ALIGNED, 0 blocking
metadata:
  type: project
---

# PR #1865 slices 4+5 actor_did convergence @ `d7216140b` (2026-06-22) — ALIGNED, 0 blocking

Branch slice45-actor-did, 2 commits over origin/main. Event-log `actor_did` cross-bridge convergence (§9.9.3). Verdict ALIGNED, 0 new blocking misalignments.

**COMMIT 1 `428e130c5` (slice 4, system-leaf sentinels):** WASM aligned UP to native (the reference). Native producers ttl.rs:679 (`"system:close"`) + ttl.rs:876 (`"system:timer"`) ALREADY use these sentinels — confirmed in the real producers, not just tests. WASM changes: manager.rs:5153 ContextExpired `""→"system:timer"`, manager.rs:6069 ContextClosed `"system"→"system:close"`. saga.rs:2110 native CrossContextDivergenceMarker `""→"system:saga"` is within-native-only (verified: NO WASM emitter of CrossContextDivergenceMarker — exists only in scp-runtime). consequence/Tombstoned/Closing `"system"` unchanged. Clamp-comment reworded (creation_timestamp_secs consumed verbatim = convergent TTL deadline base). Real-producer parity tests + pre-fix-sentinel non-vacuity controls.

**COMMIT 2 `d7216140b` (slice 5, executor-not-proposer):** PR framing HONEST — it is a WASM-quorum BUGFIX + ADR-031 attribution correction, NOT a convergence fix. Verified the "convergence premise was false" claim: WASM `execute_governance_action` (manager.rs:2910-2917) looks up proposal in pending-OR-resolved and ERRORS "is not tracked" if absent. Pre-fix WASM quorum path removed-then-executed → guard rejected → leaf NEVER MINTED. So pre-fix had NO leaf, not a divergent one. Fix reorders move-to-resolved BEFORE execute (both quorum paths manager.rs:4051, 4181) + quorum caller passes voter_did (was proposer). WASM already stamped `initiator_did`=committer on the leaf (manager.rs:2987), so WASM was executor-correct; only its caller was wrong.
  - Native: `proposal.proposer_did` → threaded `executor_did: &DID` through execute/finalize/dispatch. 4 call sites all accounted: propose auto-execute (proposer), vote quorum (voter), direct handler governance.rs:674 (proposer, proposer==committer there). No missed caller.
  - SPEC BASIS SOLID: ADR-031 (phase-6.md:2949) `GovernanceActionExecuted{executor_did: DID}` vs `GovernanceProposalCreated{proposer_did}` (2914) — distinct fields. §7.3.1 (07-spec:125) "committing member" assigns seq/timestamp. ADR-051 §6 (phase-2.md:993).

**CARVE-OUTS correctly NOT bundled (scope honesty, no silent gap):**
- #205 consequence-subject: native `finalize` keys consequences + participation on `proposal.proposer_did` (governance_helpers.rs ~4357/4423, SUBJECT semantic) — UNTOUCHED. WASM keys consequences on `initiator_did`=executor (manager.rs dispatch_consequences_for_subject). Genuine cross-bridge divergence in a DIFFERENT path (consequence eval, not leaf actor_did); separate design decision; correctly its own task.
- #206 per-action leaf event-COUNT parity: this PR only changes which actor_did is STAMPED on per-action leaves (dispatch.rs:3993 `actor = executor_did`), orthogonal to count/set parity. Not a stealth #206 fix.

GOTCHA for re-review: review target = worktree files (HEAD d7216140b), diff vs origin/main. ADR-031 lives in phase-6.md (not standalone). §7.3.1 in 07-trust-validation-and-capabilities.md.
