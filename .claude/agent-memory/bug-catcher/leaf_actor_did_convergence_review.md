# Review: native↔WASM leaf actor_did convergence (fix/leaf-actor-did-convergence)

Full-branch review 2026-06-22. Base b5b0eb02c → tip 2b668715c (4 commits incl. WASM).
Goal: native (scp-runtime) + WASM (scp-ffi-wasm) mint byte-identical Merkle leaves
for GovernanceActionExecuted + system leaves (ContextExpired/Closed), §9.9.3.

## HIGH — WASM execute capability check on VOTER diverges from native (introduced by this diff)
- `crates/scp-ffi/wasm/src/manager.rs:3000` execute_governance_action does
  `member_has_capability(initiator_did, required_capability_for_action(action))`.
- Diff switched quorum vote paths (~4373 approve, second vote fn ~4453, ~4221 propose-cross)
  to pass `voter_did` as initiator (was `proposer_did` pre-diff).
- Vote eligibility only requires `governance:vote` (4297,4453); action cap (e.g. role:assign,
  admin-only) is separate. A moderator/member voter crossing quorum → WASM execute rejects →
  ZERO leaves. Native execute (governance_helpers.rs:4489+) has NO per-action cap check →
  ONE leaf. Direct §9.9.3 divergence, non-deterministic by which member crosses quorum.
- New KAT masks it: grants voter role:assign on admin role.
- Fix: WASM execute cap-check must authorize the subject native authorizes (proposer for the
  committed proposal), or drop the redundant check (native authorizes at propose/vote time).
  Do NOT check the committing voter.

## Pre-existing (NOT this diff; task #205) — consequence subject divergence
- WASM dispatches consequences for initiator_did (manager.rs:3137) = voter on quorum path;
  native uses proposal.proposer_did (governance_helpers.rs:4358). Was initiator_did pre-diff.

## Verified CORRECT
- system_actors.rs shared consts referenced by both crates.
- finalize_close/handle_ttl_expiry deadline = creation.saturating_add(ttl) both sides;
  matches native convergent_ttl_deadline_secs; no overflow.
- WASM rollback restores Pending snapshot + removes resolved + execute removes
  executed_proposals → fully retriable. No double-remove, not lost on SingleAdmin path.
- Replay: executed_proposals + require_proposal_approved block double-leaf;
  WASM_PROPOSAL_TTL_MS now 14d = native EXECUTED_PROPOSALS_TTL_SECS.
- SingleAdmin required==0 insert-before-execute: stranded resolved-Approved is benign
  (replay-guarded; list-proposals divergence only, not a leaf divergence).
- executor threading correct on all 3 native + 3 WASM sites.
- KATs reconstruct native-reference leaf from shared primitives + non-vacuity controls; sound.
- No new panic/unwrap/index in production (all unwrap/expect under #[cfg(test)]).
