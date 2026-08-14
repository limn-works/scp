---
name: ingest-vote-wasm-convergence
description: SCP-1877 #1900 PR-2 — adding caller-trusted ingest_vote to GovernanceEngine for WASM quorum tally convergence; soundness verdict GO-WITH-CHANGES
metadata:
  type: project
---

# ingest_vote (WASM↔native governance convergence, #1900 PR-2 / SCP-1877)

GO-WITH-CHANGES verdict. Plan: add `ingest_vote(&mut self, proposal_id, voter, vote, now, context)`
to `GovernanceEngine` trait (default = OperationNotSupported); records `SignedVote { signature: Vec::new() }`
and runs SAME tally as approve/reject minus sign_vote→verify_vote. WASM holds NO signing keys / NO KeyResolver (ADR-034).

**Why mostly sound:** WASM `approve_governance_proposal` (manager.rs ~5151) + `propose_governance_action` (~4953)
ALREADY push empty-sig SignedVotes and run a MANUAL quorum tally (`approvals.len() >= required`) then set
`status = Approved`. So "Approved ⟹ verified sigs" is ALREADY relaxed for WASM today. ingest_vote moves that
manual tally into the shared engine = strictly better (single tally implementation, less drift). No NEW trust relaxation.

**Native trust boundary CONFIRMED intact:** governance_helpers.rs:4918 resolves proposal from `engine.get_proposal()`
(engine's OWN state, never caller-supplied) and trusts `status==Approved` WITHOUT re-verifying sigs at execute.
The engines set Approved only after verify_vote at genuine quorum (multisig/majority/unanimity all verify_vote before push).
So native's guarantee depends entirely on native NEVER calling ingest_vote.

**verify_proposal_votes:** exists (mod.rs:290) but has ZERO production callers (test-only). So no native consumer
re-verifies a deserialized proposal's votes. Cross-bridge import of a WASM-resolved proposal into native does NOT happen:
export_import.rs proposals carry `approvals: vec![]` (the :1583 Approved hit is test-only). Native engines are in-memory;
proposals aren't deserialized-then-trusted across the WASM→native boundary.

**REQUIRED CHANGES (the "with-changes"):**
1. Native must NEVER call ingest_vote. Default-trait OperationNotSupported is insufficient — the three real engines
   (multisig/majority/unanimity) would each need to NOT override it. Pin with a test asserting each native engine's
   ingest_vote returns OperationNotSupported, OR (better) gate ingest_vote impls behind a wasm-only seam so native
   physically can't reach a non-erroring impl. The refactor extracting `record_vote_and_resolve` MUST keep verify_vote
   on the signed path — add a test that a forged-sig approve() still returns InvalidSignature after the refactor
   (the existing forged_vote_signature_rejected / e2e_valid_votes... tests in multisig.rs:1594/1678 PIN this; ensure
   majority+unanimity have equivalents and that they survive the record_vote_and_resolve extraction).
2. Boundary guarantee ingest_vote relies on (document in the method's rustdoc as a caller contract):
   caller MUST authenticate (a) voter identity == claimed voter_did, (b) voter holds governance:vote in THIS context,
   (c) proposal_id belongs to this context/engine, (d) no double-vote (has_voted dedup is inside record_vote_and_resolve — OK).
   WASM provides (a) via single-origin + no remote vote-ingest path, (b) via member_has_capability("governance:vote")
   at manager.rs:5099 BEFORE calling, (c) via per-context engine keyed by context_id, (d) via engine dedup.
3. RESIDUAL GAP (LOW, pre-existing, not introduced): a malicious JS caller in the SAME browser origin can call
   approve for ANY voter_did that is a member (no per-vote signature binds the vote to the human key in WASM).
   This is inherent to ADR-034 (no keys in WASM) and is UNCHANGED by ingest_vote — the empty-sig model already had it.
   Equivocation/cross-bridge divergence is the real protection (native would reject a WASM-minted leaf only if roots
   diverge; identical tally keeps roots equal). Flag as accepted ADR-034 limitation, not a regression.
4. `now` is committer-assigned (manager.rs uses now_secs stamped on the SignedVote AND the convergent leaf timestamp).
   ingest_vote must take `now` as a param (NOT read a clock) so WASM passes the SAME convergent value it stamps on the
   GovernanceVoteCast leaf — otherwise vote.timestamp (in tally-irrelevant but proposal-state) could differ from the leaf
   and, more importantly, native's approve() uses context.now. Since empty-sig votes' timestamp never feeds a signature,
   replay/equivocation risk from `now` is nil for the TALLY; the only constraint is leaf-timestamp convergence, already
   handled by passing the committer-assigned now. OK as designed.

**Key files:** trait + invariant mod.rs:988-993 (Approved⟹verified) / sign_vote:218 / verify_vote:248 / verify_proposal_votes:290.
Engines: multisig.rs approve:330 reject:410 (verify before push:385/465); majority.rs approve:386 reject:480 (verify:443/536);
unanimity.rs propose:208. WASM: manager.rs propose:4889 approve:5090 reject:5239 require_proposal_approved:3397 execute:3486.
Native execute precondition: governance_helpers.rs:4918.
