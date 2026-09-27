# A Governance Helper That Errors After a Durable Effect Must Not Make Its Proposal Retryable

## The failure

`execute_governance_action` in `crates/scp-runtime/src/context/governance_helpers.rs` once
treated every dispatch error as "retry this proposal": it removed the proposal id from
`executed_proposals`, so the caller could re-send it. Pull request #2276 then turned two
post-commit `KeyEpochAdvance` appends from warn-and-continue into `?`, on the stated premise
that `?` "rolls nothing back". Inside the helper that was true; the caller rolled back the
replay marker. `governance_ban_subscriber` and `rotate_all_author_keys` are not idempotent,
so a second run advanced every author's epoch again and appended a second `AccessRevoked`
leaf. The retrying member's log then diverged permanently, and §9.9.3 of
`09-security-model.md`, which compares Merkle roots at equal event counts, reads that
divergence as equivocation.

## The rule

After a helper has applied a durable effect, an `Err` is a false report: it tells the caller
the revoke did not happen when it did, and it re-opens the replay window. Log each failed
leaf at ERROR with the context id, the subject DID, and the error; continue with the remaining
leaves; and credit `checkpoint_events_since` for the leaves that landed.

## How the class is closed

Editing each `execute_*` helper would let the next one reintroduce the shape, so the replay
marker decides from a counter. `ClassSCell` (`crates/scp-runtime/src/context/actor/class_s.rs`)
is the only route to a mutable view of context state, and it counts hand-outs in
`mutation_epoch`. `execute_governance_action` reads the epoch before dispatch and again on a
dispatch error:

- **Epoch unchanged:** nothing landed, so the marker is removed and the proposal is retryable.
- **Epoch changed:** a mutation or leaf landed, so the marker stays (persisted fail-closed),
  `finalize_governance_action` does not run, and the error reaches the caller with an ERROR
  log. `discharge_and_order_governance_action` still removes the proposal from
  `approved_proposals` inside that same persist, or the stale entry would block every later
  conflicting proposal.

Consequences for a helper author:

- A helper that appends a per-attempt leaf and then returns `Err` by design consumes its
  proposal. `execute_extend_ttl` appends `TtlExtensionRejected` when consent is short of
  unanimous, so members submit a new `ExtendTtl` proposal.
- A helper whose pre-checks must leave the proposal retryable reads through the cell's
  `Deref` and takes no `class_c_view` before its first commit.
- The cell counts a hand-out and cannot see a later hand-out undo it, so stage state only
  after the fallible step succeeds. `execute_propose_context_migration` now stages
  `migration_state` after `create_context` succeeds.

`crates/scp-runtime/src/context/actor/handlers/broadcast.rs` holds the tests that pin each
outcome, among them `anchor_leaf_failure_after_commit_keeps_marker_and_blocks_re_execution`
and `pre_effect_dispatch_error_drops_marker_so_the_proposal_is_retryable`.
