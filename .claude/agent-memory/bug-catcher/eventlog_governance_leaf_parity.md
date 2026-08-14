---
name: eventlog-governance-leaf-parity
description: WASM governance proposal/vote leaves carry proposal_id payload while native uses empty payload — breaks native↔WASM Merkle root convergence (§9.9.3)
metadata:
  type: project
---

# WASM↔native governance leaf payload divergence (HIGH)

Found on branch eventlog phase-2 substrate swap (HEAD 4cad781e5), file
`crates/scp-ffi/wasm/src/manager.rs`.

**Bug:** WASM `append_log_event` for `GovernanceProposalCreated` (line ~3947),
`GovernanceVoteCast` (lines ~4066 and ~4178), and `GovernanceVoteWithdrawn`
(line ~4251) all pass `proposal_id.as_bytes()` as the leaf payload. Native
`governance_helpers.rs` emits these same event types via `append_context_event`
→ `EventPayload::default()` (EMPTY payload — builder.rs:194). Leaf preimage is
`SHA-256(0x00 ‖ rmp_serde(Event))` and `Event.payload` differs → divergent leaf
hashes → divergent `tree::root` → FALSE-POSITIVE §9.9.3 equivocation detection
on any mixed native/WASM context that ever created a proposal or cast a vote.

**Why missed:** PR added `cross_impl_*_leaf_bytes` parity tests for
GovernanceActionExecuted, TokenRevoked, ConsequenceTriggered — but NOT for
GovernanceProposalCreated/VoteCast/VoteWithdrawn. The author DID fix the same
class for `ToolRegistered` (made WASM empty to match native, with an explicit
comment) but missed the three governance proposal/vote types.

**Fix:** WASM must pass `b""` (empty) for these three event types to match
native's empty-payload convention, AND add cross-impl leaf-byte parity tests for
them. (proposal_id is NOT part of native's canonical leaf.)

**RECURRING PATTERN:** native↔WASM leaf-byte parity requires checking EVERY
durable EventType's payload on both sides. Per-type parity tests only cover the
3 most-obvious types; the long tail (proposal/vote lifecycle) drifted. Always
enumerate all durable leaf-emitting EventTypes and confirm payload byte-parity.
