---
name: leaf-actor-did-convergence
description: Branch fix/leaf-actor-did-convergence (2b668715c) — native↔WASM §9.9.3 leaf parity for GovernanceActionExecuted executor-stamp + ContextClosed convergent TTL deadline + system-actor const hoist; SOUND
metadata:
  type: project
---

Branch `fix/leaf-actor-did-convergence` (HEAD 2b668715c), reviewed 2026-06-22. Verdict: SOUND, no blocking findings.

**Scope:** closes 2 more native↔WASM divergent leaves in the §9.9.3 equivocation substrate. Durable leaf = SHA-256(0x00 ‖ rmp_serde(Event)); Event positional fields {event_type, actor_did, timestamp, sequence, payload, prev_hash, signature:[]}.

**(a) GovernanceActionExecuted executor-stamp.** Pre-fix native stamped `proposal.proposer_did`; WASM stamped `initiator_did` (caller). Fix threads `executor_did` through native execute/dispatch/finalize (governance_helpers.rs) and adds it to WASM `execute_governance_action`. Convergent on all 3 paths:
- quorum: executor = quorum-crossing VOTER (native vote_on_proposal_inner passes voter_did; WASM vote handler passes voter_did)
- auto-execute (SingleAdmin/quorum=0): executor = proposer (both sides)
- direct-FFI: executor = proposal.proposer_did (native handle_execute_governance_action_actor; WASM context_execute_governance:772 resolves via proposal_proposer_did then passes as executor — `initiator_did` stays auth-subject only)
Leaf timestamp = proposal.created_at on BOTH (native finalize_governance_action; WASM proposal_created_at lookup, fails closed if untracked). Payload = encode_payload(GovernanceActionExecutedPayload{target_did: action.target_did().unwrap_or_default(), action_type: action.variant_name()}) — shared scp_protocol::context::governance::GovernanceAction methods on both → byte-identical. WASM fails CLOSED on encode error now (was unwrap_or_default → empty-payload divergence). WASM also requires status==Approved precondition (mirrors native) + inserts proposal Approved BEFORE execute + rolls back on dispatch failure (retry parity).

**(b) ContextClosed convergent TTL deadline.** WASM finalize_close was local now_secs(); fix → `match ttl_seconds { Some(ttl)=>creation+ttl, None=>now }`. Native finalize_close stamps deadline_unix_secs.unwrap_or_else(now) where deadline_unix_secs = creation+ttl (ttl_close_helpers convergent_ttl_deadline_secs). MATCH for TTL case. No-TTL case: both fall back to local now() (symmetric, documented, no convergent value exists).
- TTL-extension governance ExtendTtl: WASM `ttl_seconds += additional` (manager:3225) → creation+(ttl+add). Native execute_extend_ttl `deadline_unix_secs += additional` (governance_helpers:1556) → (creation+ttl)+add. MATCH.
- ContextExpired (handle_ttl_expiry) same convergent stamping, no creation==0 guard (0+ttl convergent, fail-safe).

**System-actor const hoist (scp-event-log/src/system_actors.rs).** SYSTEM_TIMER_ACTOR="system:timer", SYSTEM_CLOSE_ACTOR="system:close", SYSTEM_CONSEQUENCE_ACTOR="system" — all byte-identical to pre-hoist literals (verified against b5b0eb02c). SYSTEM_SAGA_ACTOR="system:saga" is a VALUE CHANGE (native saga emit_divergence_marker was "" → "system:saga", saga.rs:2110). SAFE: WASM never emits CrossContextDivergenceMarker (native-only leaf, no cross-impl counterpart); actor_did is OUTER leaf field, NOT part of inner signed CrossContextDivergenceMarker::sign payload → no sig break. Pre-release, no migration concern.

**KATs (WASM consequence.rs cross_impl_leaf_parity).** Strong methodology: native_reference_single_{system,payload}_leaf_root() reconstructs Event from shared scp_event_log primitives (sequence:0, GENESIS_PREV_HASH, sig:[]), append_unsigned_event+root → compares vs WASM real-producer test_context_event_log_root. PINS THE MERKLE ROOT, not just a field. 4 tests w/ non-vacuity controls: direct-execute proposer-stamp, ContextClosed convergent-deadline, system-leaf actor sentinels (expired/closed), quorum executor-stamp (drives real propose+approve). Both native-real and WASM-real build identical Event shape via same append_unsigned_event (providers/event_log.rs:89 vs manager.rs:473) → cross-impl byte parity by construction. Native integration test (governance_integration.rs) drives REAL quorum via Supervisor+MerkleEventLogProvider, asserts leaf actor=bob(voter) not alice(proposer).

**Bundled hardening:** WASM_PROPOSAL_TTL_MS 24h→14d (= native EXECUTED_PROPOSALS_TTL_SECS state.rs:73). Closes a real replay-window divergence (WASM could re-mint executed leaf in 24h-14d window native rejects). Correct.

**Residual/out-of-scope (NOT regressions):**
- Consequence-leaf SUBJECT convergence (native proposer vs WASM executor) = task #205, separate slice. This diff only hoists the "system" actor const (value-preserving).
- Consensual reset_ttl_timer (non-governance unanimous extension): native arms local-clock (deadline_override=None, ttl_close_helpers:220-227), WASM mutates ttl_seconds (convergent). DIVERGENT but documented ADR-051 forward step; not one of the 2 targeted leaves.
- Native ExtendTtl mutates deadline_unix_secs but NOT params.ttl → native restore recomputes creation+original_ttl (loses extension) while WASM snapshot carries extended ttl_seconds. Native-internal restore consistency concern, latent, not this diff's leaves.
