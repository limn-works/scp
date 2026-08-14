---
name: pr1865-governance-executor-stamp
description: Black-hat review of PR #1865 (executor-not-proposer stamp + WASM quorum reorder + system-leaf sentinels); holds
metadata:
  type: project
---

# PR #1865 (HEAD d7216140b) — executor stamp + WASM reorder. Adversarial review: HOLDS.

Branch slice45-actor-did. Two commits. Reviewed for double-execute/replay, attribution spoofing, attacker-chosen executor DID.

## Commit 2 (d7216140b) findings — all HOLD
1. WASM quorum reorder (remove-pending → set Approved → insert-resolved → execute):
   - Pre-fix the quorum/auto-execute path removed-from-pending THEN executed, so
     `execute_governance_action`'s pending-or-resolved tracking guard (manager.rs:2909)
     errored via `?`. Single-voter/quorum==1 propose auto-execute was a LATENT BUG (errored
     out, never minted leaf). Reorder fixes it. NOT a vuln introduction.
   - No double-execute: `executed_proposals.contains_key` replay guard (manager.rs:2902) +
     insert-before-dispatch (2928). Second approve fails at `pending_proposals.get_mut`
     (proposal already moved to resolved). Backstop holds.
2. Executor attribution (voter_did as committer) is SOUND on native: engine `approve()`
   (majority.rs:429-448) signs with passed signing_key but VERIFIES sig against the
   DID-resolved Active key via key_resolver. Passing voter_did=victim with own key FAILS
   verify_vote. Non-spoofable.
3. WASM does NOT verify vote sigs (approve_governance_proposal records SignedVote{signature:
   Vec::new()}, only member_has_capability check). voter_did is CALLER-ASSERTED. Pre-existing
   per ADR-034 (WASM is single-user local client; remote votes don't flow through these
   methods). Commit stamps that asserted voter as executor but adds no NEW spoof surface.
4. Native executor_did threading: never a free FFI payload field at the leaf. Quorum=voter_did
   (verified), auto-exec=proposer_did, direct=proposal.proposer_did.

## Pre-existing (NOT introduced by this commit; out of scope #205/#206)
- Direct `governance_execute` (scp-ffi/src/context.rs:3045, NAPI/UniFFI twins) deserializes a
  CALLER-SUPPLIED GovernanceProposal JSON: status, proposer_did, approvals all attacker-set.
  execute checks status==Approved (caller sets it). Caller can mint a GovernanceActionExecuted
  leaf attributing exec to ANY DID. Leaf bytes UNCHANGED by commit (was already proposer_did).
  Deeper issue: this direct path trusts a caller proposal blob with no engine-side quorum/sig
  re-verification. Worth a separate finding if direct-execute is meant to be authenticated.

## Commit 1 (428e130c5) — system-leaf sentinels — HOLDS
- "" / "system" → "system:timer" / "system:close" / "system:saga". These are NOT valid DIDs
  (DID = did:{method}:{id}), so no member can register a colliding DID; no misattribution and
  no forging system events as member-originated. Reserved namespace. Sound.
