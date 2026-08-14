---
name: trusted-vote-ingest-pr2a
description: API review of keyless TrustedVoteIngest governance trait (commits 824d7a61e + docs-only d7fb44f9b, worktree 1900-pr2a-engine) — APPROVED twice
metadata:
  type: project
---

# TrustedVoteIngest keyless governance trait — APPROVED (2026-06-27)

Commit 824d7a61e ("fix(governance): run vote guards before signature verification; dedup unsigned-vote build"), engine-layer PR-2a in a stack. File: crates/scp-protocol/src/context/governance/mod.rs + majority.rs/multisig.rs/unanimity.rs.

**What:** New public `pub trait TrustedVoteIngest { ingest_approve/ingest_reject(&mut self, proposal_id, voter, context) }` — keyless counterpart to signed `approve`/`reject` (which need SigningKey + KeyResolver). For WASM no-key custody (ADR-034) to reuse the EXACT quorum tally instead of a divergent reimpl. Impl'd ONLY on the 3 multi-party engines (Majority/Threshold/Unanimity), NOT SingleAdmin. No external callers yet (WASM wiring is downstream in the stack).

**Why APPROVED (verdict clean, no blocking changes):**
- Two-method surface = signed signature minus the 2 key-bearing params. Reads `now` from GovernanceContext::now (NOT a param) — correct; a timestamp param would be a footgun breaking native↔WASM root convergence.
- Trust-boundary rustdoc is exemplary: numbered MUST preconditions (identity==voter, governance:vote in THIS context, proposal scoping), bold "NO signature verification", explicit "Approved⟹verified does NOT hold here", residual-risk + §9.9.3 equivocation/Merkle compensating control, and the crucial scoping that caller is trusted ONLY to assert WHICH eligible member voted (eligibility/dedup/deadline/finality still enforced by shared tally).
- GovernanceProposal::status invariant now correctly conditioned "signed path only" with cross-link to the keyless exception.
- **Separate-trait containment is REAL type enforcement:** native holds `Box<dyn GovernanceEngine>` which has no `ingest_*` in vtable → keyless path unreachable from native by construction. Better than a runtime-guarded method on GovernanceEngine (which would be a silent-security-default footgun).
- **push_and_resolve kept PRIVATE (not a default trait method) is the key call:** prevents a caller injecting an arbitrary pre-built SignedVote and bypassing precheck guards. ingest_* is the only public entry; vote always built internally via build_unsigned_vote.
- PrecheckOutcome{Proceed,Resolved} is pub(super), never in a public signature — clean internal abstraction. Resolved arm only fires for Majority past-deadline auto-resolve; threshold/unanimity carry the dead-but-defensive arm DELIBERATELY for call-site uniformity (don't let a future simplifier strip it).
- build_unsigned_vote pub(super), dedups 4 hand-rolled `signature: Vec::new()` literals into one documented site. Correct scope.
- No DOA, no over-engineering: containment is pure type-system reachability + rustdoc, zero new gates/validators.

**Re-reviewed at d7fb44f9b (docs-only delta over 824d7a61e):** commit only corrects the push_and_resolve borrow comment + PrecheckOutcome doc on mod/multisig/unanimity. No public-API change. Still APPROVED. Two additional non-blocking observations this pass: (1) TrustedVoteIngest is NOT in the `pub use governance::{...}` re-export at context/mod.rs:35 though sibling GovernanceEngine IS — consumer imports the two traits from different paths; deliberate-decision flag, not a bug. (2) Zero in-repo consumers at this commit (WASM bridge caller is downstream) — integration checklist (fn→ContextManager→bridge→SDK wrapper→pipeline assertion→capability matrix) must be tracked to closure; an exported pub trait with no caller is half-wired per "done at every layer".

**Patterns reinforced:** (1) keyless/trusted FFI paths belong in a SEPARATE trait off the dyn vtable, not a flag on the main trait; (2) keep the "record pre-built object" helper private so the guarded entry point is the only public surface; (3) read clock from context, never accept a timestamp param on a tally path.
