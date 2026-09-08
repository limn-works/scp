# A post-commit `?` in a governance helper re-arms the proposal replay marker

**Source:** `execute_governance_action` and the `execute_*` per-action leaf
helpers in `crates/scp-runtime/src/context/governance_helpers.rs`; §9.9.3 of the
security-model spec, `.docs/specs/09-security-model.md`, which detects
equivocation by comparing Merkle roots at the same event count.

## The rule

A `dispatch_governance_action` helper must not return `Err` after it has applied
a durable effect. `execute_governance_action`
(`crates/scp-runtime/src/context/governance_helpers.rs`) treats every dispatch
error as "retry this proposal": it removes the proposal id from
`executed_proposals` and persists the removal fail-closed. A caller may then
re-send the same proposal id, and the helper runs again from the top.

## What that costs when the action is not idempotent

`governance_ban_subscriber`
(`crates/scp-protocol/src/context/broadcast/mod.rs`) inserts the DID into
`banned_subscribers` and then rotates every author's broadcast key. No branch
skips the rotation for an already-banned DID, so a second run advances every
author's epoch a second time and appends a second `AccessRevoked` leaf.
`rotate_all_author_keys` behaves the same way for `RotateContentKeys`. The
member that retried then holds more leaves, at a higher epoch, than every member
that applied the commit once, so the §9.9.3 equal-count / equal-root consistency
test fails on it and keeps failing.

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

## The residue this lesson does not close

The anchor-leaf append of nearly every `execute_*` helper carries the same
shape: `commit_class_s_keep` persists the mutation, then a `?`-fallible
`append_context_event*` can fail and re-arm the marker.
`execute_reconfigure_governance` has it twice, at its `GovernanceReconfigured`
leaf and at its `GovernanceDeadlockRecovery` companion. Closing that class needs
the dispatch error channel to distinguish a failure raised before any durable
effect from one raised after it, which is a change to the replay-marker contract
in `execute_governance_action` rather than an edit to the helpers.
