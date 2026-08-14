---
name: pr2a-governance-precheck-split
description: Adversarial audit of d7fb44f9b precheck_vote/push_and_resolve split + keyless TrustedVoteIngest in scp-protocol governance engines — verdict GO
metadata:
  type: project
---

# PR2A governance precheck/push split + TrustedVoteIngest (commit d7fb44f9b)

Verdict: **GO** (no findings introduced by this refactor). Audited 2026-06-27.

**Change:** split each engine's vote handling into `precheck_vote` (guards →
PrecheckOutcome::{Proceed,Resolved}) + `push_and_resolve` (push+tally). Added
keyless `TrustedVoteIngest::{ingest_approve,ingest_reject}` for the WASM bridge
(ADR-034) that runs precheck → empty-sig vote → push_and_resolve, NO verify.

## Verified SOUND (compile + runtime probes):
- **No native upcast to keyless path.** `Box<dyn GovernanceEngine>.ingest_approve(..)`
  → compile error E0599 (proven). GovernanceEngine supertrait = `Send+Sync` only,
  no TrustedVoteIngest supertrait, no blanket impl. TrustedVoteIngest is `pub` but
  deliberately NOT re-exported from `context::governance` facade (omitted from
  `pub use governance::{...}` in context/mod.rs) — only reachable via full path.
  Native always runs signed approve/reject (verify before count).
- **Guard ordering preserved.** precheck runs BEFORE sign/verify on signed path:
  NotEligible/AlreadyVoted fire regardless of which key signed. dedup is by
  voter_did only (signature-independent) → that's WHY it must precede verify.
- **verify stays strictly before push.** push_and_resolve only reached after
  verify_vote succeeds on signed path. No path counts an unverified vote on the
  signed flow.
- **Signed vs ingest reach IDENTICAL ProposalStatus** for same config+sequence
  (tally is shared + signature-independent). No equivocation lever within one
  honest impl. Confirmed approve AND reject sequences.
- **has_voted (all 3 engines)** checks approvals OR rejections by voter_did →
  cannot approve-then-reject or mix signed/ingest to double-count.
- **Terminal/deadline guards** fire on keyless path: terminal→ProposalNotPending,
  past-deadline→defers to deterministic resolve() (InsufficientParticipation),
  not attacker-controllable.
- **Equivocation compensating control is REAL.** Empty-sig vote (Vec::new(), len 0)
  fails verify_vote at `try_into::<[u8;64]>()` → "signature must be 64 bytes, got 0".
  verify_proposal_votes calls verify_vote on every vote → honest native participant
  deterministically rejects keyless proposal → event-log roots diverge → detectable.

## Pre-existing, NOT introduced by this PR (do not re-flag):
- Majority early-approval `approvals*2 > eligible` IGNORES quorum_bps (2-of-3 at
  quorum=10000 still Approved). This is documented design (absolute majority of
  whole set implies quorum moot); identical at 824d7a61e~3 line 245. resolve()
  applies quorum only on deadline path with no absolute majority.

## Residual (acknowledged in doc, inherent to ADR-034):
- Same-origin WASM host can ingest a vote for any eligible member without their
  sig. Doc §"Residual risk" owns this; compensating control = §9.9.3 equivocation.
  TrustedVoteIngest has ZERO callers in-tree at d7fb44f9b (WASM wiring is a later PR).
