# A post-commit `?` in a governance helper re-arms the proposal replay marker

**Source:** `execute_governance_action` and the `execute_*` per-action leaf
helpers in `crates/scp-runtime/src/context/governance_helpers.rs`; §9.9.3 of the
security-model spec, `.docs/specs/09-security-model.md`, which detects
equivocation by comparing Merkle roots at the same event count.

## The rule

A `dispatch_governance_action` helper must not return `Err` after it has applied
a durable effect. Until pull request #2276, the branch that makes broadcast
author ordering deterministic by construction, `execute_governance_action`
(`crates/scp-runtime/src/context/governance_helpers.rs`) treated every dispatch
error as "retry this proposal": it removed the proposal id from
`executed_proposals` and persisted the removal fail-closed. A caller could then
re-send the same proposal id, and the helper ran again from the top.

## What that costs when the action is not idempotent

`governance_ban_subscriber`
(`crates/scp-protocol/src/context/broadcast/mod.rs`) inserts the DID into
`banned_subscribers` and then rotates every author's broadcast key. No branch
skips the rotation for an already-banned DID, so a second run advances every
author's epoch a second time and appends a second `AccessRevoked` leaf.
`rotate_all_author_keys` behaves the same way for `RotateContentKeys`. The
member that retried then holds more leaves, at a higher epoch, than every member
that applied the commit once. Its log stays divergent from then on, so its
`ConsistencyCheckpoint` never matches an honest member's: the count runs ahead,
and at any count where the two coincide the Merkle roots differ, which §9.9.3
reads as equivocation.

## How the branch introduced it

Pull request #2276, the branch that makes broadcast author ordering
deterministic by construction, converted the two post-commit `KeyEpochAdvance`
loops from warn-and-continue to `?`. Its comment argued the conversion was safe:

> DURABILITY-SIGNALLING, NOT FAIL-ATOMIC. `?`-propagating an append failure
> rolls nothing back

The premise names the wrong scope. The `?` rolls nothing back *inside the
helper*, and the caller rolls back the replay marker. An author who reads only
the helper cannot see that, which is why the comment now names the caller.

## What to write instead

Log each miss at ERROR with the context id, the subject DID, and the underlying
error, continue to the remaining leaves, and credit `checkpoint_events_since`
inline in the success arm so the leaves that landed are still counted. An `Err`
return after the effects landed is a false report: it tells the caller "the
revoke did not happen" about a revoke that did happen, and it opens the replay
window. A log line is an honest report of the same fact and opens nothing.

## How the class is closed

The anchor-leaf append of nearly every `execute_*` helper carries the same
shape: `commit_class_s_keep` persists the mutation, then a `?`-fallible
`append_context_event*` can fail. `execute_reconfigure_governance` has it
twice, at its `GovernanceReconfigured` leaf and at its
`GovernanceDeadlockRecovery` companion. Editing every helper would leave the
next helper's author free to reintroduce the shape, so the closure lives in the
replay-marker contract instead.

`ClassSCell` (`crates/scp-runtime/src/context/actor/class_s.rs`) is the only
route to a mutable view of a context's state: it has no `DerefMut` and no
`state_mut`, and every combinator, token discharge, and `class_c_view` call
constructs the view inside the cell. The cell now counts those hand-outs in
`mutation_epoch`, and each combinator advances the count at the point where a
mutation survives it: a keep-direction combinator counts once `f` returns
`Ok`, a restore-direction combinator counts only once its persist lands, and a
view accessor counts at the hand-out because the cell cannot see which field
the view touched. A landed leaf counts too, because the helper that appended it
credits `checkpoint_events_since` through `class_c_view`.

`execute_governance_action` reads the epoch after it has marked the proposal
executed and before it dispatches. On a dispatch error it reads the epoch
again. An unchanged epoch proves the helper applied nothing, so the marker is
removed and the proposal stays retryable. A changed epoch means an effect
landed, so the marker stays, finalize runs as it would after `Ok`, and the
dispatch error reaches the caller with an ERROR log naming the context and the
proposal. `key_epoch_advance_failure_keeps_executed_proposal_marker`,
`anchor_leaf_failure_after_commit_keeps_marker_and_blocks_re_execution`, and
`pre_effect_dispatch_error_drops_marker_so_the_proposal_is_retryable` in
`crates/scp-runtime/src/context/actor/handlers/broadcast.rs` pin the three
outcomes.

One consequence a helper author must know: a helper that records a per-attempt
leaf and then returns `Err` by design consumes its proposal. `execute_extend_ttl`
appends a `TtlExtensionRejected` leaf when consent is short of unanimous and
returns `PermissionDenied`; that leaf advances the epoch, so the same proposal id
cannot be executed again, and the members submit a new `ExtendTtl` proposal once
consent is unanimous. A helper whose pre-checks must leave a proposal retryable
reads through the cell's `Deref` and takes no `class_c_view` before its first
commit; `execute_reset_member` reads `cell.handle` and `cell.membership` that way.
