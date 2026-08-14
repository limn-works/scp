---
name: governance-precheck-ingest-split
description: Audit of governance precheck_vote/push_and_resolve split + keyless TrustedVoteIngest (commit 824d7a61e) — verdict GO
metadata:
  type: project
---

# Governance vote-handling split + keyless ingest (commit 824d7a61e)

Audited commit `824d7a61e` (scp-protocol governance: mod/multisig/majority/unanimity).
NOTE: branch was later rewritten — `824d7a61e` is NOT an ancestor of the current
detached HEAD; the precheck/ingest design was REPLACED in `1620de983` (governance
files rewritten, -1312 lines). Audit was done against `824d7a61e` via an isolated
`git worktree add --detach /tmp/bh_824 824d7a61e` because the in-tree files are stale.

**Verdict: GO.** Design is sound. No way found to count an unverified vote on the signed path.

## Why it holds
- Signed path (all 3 engines): precheck -> sign -> verify_vote -> push_and_resolve,
  with verify STRICTLY before push. Probe `bh_signed_bad_key_errors_but_ingest_counts`
  proved a wrong-key vote errors InvalidSignature and is NOT recorded (approvals stays N).
- Tally (`evaluate_resolution`/`resolve`/`resolve_proposal`) counts `approvals.len()`/
  `rejections.len()` only — NEVER inspects `vote.signature`. So an honest ingest (empty
  sig) and a verified signed vote reach IDENTICAL status. The only signature-inspecting
  code in these files is checkpoint COSIGNATURE verify (ADR-031 §9), a separate concern.
- Native cannot reach keyless ingest. PROVED by compile-fail probes in /tmp/bh_824:
  - `Box<dyn GovernanceEngine>.ingest_approve(...)` -> E0599 (no such method).
  - Even `use governance::TrustedVoteIngest;` then `dyn GovernanceEngine` -> E0599
    (separate trait, not a supertrait; no Any/downcast; no blanket impl).
  - TrustedVoteIngest is NOT in the `context::governance` re-export list (extra friction).
  - state.rs construction sites build concrete engine in a `let`, immediately `Box::new`
    -> type erased; trait not imported in those fns.
- Majority `&mut self` precheck past-deadline auto-resolve is NOT an attack: eligibility
  gate runs FIRST (non-members get NotEligible, can't trigger). Resolve injects NO vote —
  only finalizes the EXISTING tally, deterministically, identical to the timeout task's
  `engine.resolve()` (timeout.rs:373). No "lock favorable tally" — attacker can't change it.
- Quorum math untouched by the refactor and off-by-one-clean: threshold `approvals>=t`;
  majority strict `approvals*2>eligible` (2-2 tie does NOT early-approve); push_and_resolve
  inline predicates byte-match the inherent resolve().
- Ingest enforces eligibility/dedup/deadline/terminal for all 3 engines (precheck shared).

## The one intended divergence (documented, mitigated)
Signed-bad-sig errors where ingest counts. This is ADR-034 no-key custody by design;
compensating control = §9.9.3 equivocation/Merkle-root convergence (honest signed
participant rejects the unverifiable vote -> roots diverge -> detectable). 365/365
governance tests pass at 824d7a61e.
