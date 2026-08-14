# PR #2234 — `checkpoint_events_since` / KEA fail-closed (rev 432691d70)

## What the counter actually is
- `PerContextState::checkpoint_events_since` (state.rs:973), Class-C, `#[serde]`-persisted.
- SOLE consumer: `queries_helpers::create_checkpoint_if_due_view` — `events_due = >= 50`,
  `time_due = events_since > 0 && now - last >= 600`. Reset to 0 on checkpoint.
- `build_checkpoint` (queries_helpers.rs:734) reads `event_count` + `merkle_root` from the
  **event log itself**, NOT from the counter. ⇒ an off-by-N only shifts checkpoint TIMING;
  it never corrupts checkpoint contents. Impact = §9.9.3 checkpoint-position drift
  (members checkpoint at different event counts ⇒ fewer equal-count comparisons).

## Counter trace verdict (3 routed fns)
`execute_reconfigure_governance` / `execute_rotate_content_keys` / `execute_revoke`:
counter == durable-leaf count on EVERY non-cancelled path (early returns, both append-fail
positions, mid-KEA-loop fail). Inline per-leaf bump is correct. ✅

## Structural problems found (still open)
1. **"Durable" is a lie one layer down.** `MerkleEventLogProvider::append_event`
   (providers/event_log.rs:686) mutates the in-memory Merkle tree synchronously then calls
   `persist_entry_best_effort` — **swallows storage errors and returns `Ok`**. So
   fail-closed KEA is only fail-closed vs the in-memory tree. The append essentially never
   Errs in prod (only "no event log for context").
2. **Cancellation under-count.** `handle_execute_governance_action_actor`
   (handlers/governance.rs:693) wraps the whole thing in `tokio::time::timeout(HANDLER_TIMEOUT, …)`.
   Cancellation at the `persist_entry_best_effort().await` INSIDE `append_event` leaves the
   leaf in the tree with the `+= 1` unreached. Post-await bumps + Class-C coalesced persist
   cannot deliver the exactness the comments claim.
3. **3 identical stale sites left in the same file**: `withdraw_governance_vote` (416-437),
   `propose_governance_action_inner` (4053-4085), `vote_on_proposal_inner` (4385-4414) —
   accumulate-then-bump-after-loop, `?` in loop ⇒ under-count on partial failure.
4. **Fix the class, not the sites.** ~40 hand-maintained `+= 1` call sites is non-convergent.
   Derive `events_since` from log position at last checkpoint (sound by construction).

## KEA convergence premise (unverified)
Every `EventType::KeyEpochAdvance` append site is EXECUTOR-side only
(governance_helpers 1006/3204, broadcast_helpers 276/736). Found NO receive-side append.
If remote members never mint KEA leaves, "convergent governance trigger → convergent leaf"
is false and equal-count/equal-root is already broken on broadcast contexts. VERIFY.

## Doctrinal inconsistency
`unsubscribe_broadcast` + `block_broadcast_subscriber` KEA leaves stay BEST-EFFORT durable
leaves. ADR-011 (governance_logic.rs:153-158) gives two options — durable leaf (convergent
trigger) or buffer-only (non-convergent). "Sometimes in the log" is the one option it forbids.
The PR's new rationale conflates ADR-049 §9 authorization-DIRECTION with ADR-011 log CONVERGENCE.

## Well-defended
- Determinism sorts (`sort_unstable_by(author_did)`) in `rotate_all_author_keys`,
  `governance_ban_subscriber`, `unsubscribe` — total order on unique HashMap keys, single
  return path each, asserted without re-sorting in tests. Sound.
- `SeedBroadcastAuthor` test seam gated `#[cfg(feature="testing")]` at all 5 layers
  (enum variant, dispatch arm, ClassCMut method, Supervisor method, router). `testing` is
  not default. NOT a production nullifier.
