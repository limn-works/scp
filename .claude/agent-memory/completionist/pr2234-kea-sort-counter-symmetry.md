---
name: pr2234-kea-sort-counter-symmetry
description: PR #2234 fix/rotate-content-keys-review-followup — broadcast KEA-leaf sort + checkpoint-counter fail-closed fixes; round-3 residual gaps (test coverage, non-uniform pattern, block-KEA spec silence)
metadata:
  type: project
---

# PR #2234 KEA sort + counter symmetry (rounds 1-3)

Fix for broadcast KeyEpochAdvance (KEA) leaf Merkle-determinism (§9.9.3) + checkpoint-counter drift + ADR-011 fail-closed classification.

## Round-3 state (@origin/fix/rotate-content-keys-review-followup, 7 commits off origin/main)

**RESOLVED from round-2:** the previously-missed unsubscribe path now BOTH sorts (protocol mod.rs:850) AND counts (unsubscribe_broadcast kea_success_count). All 3 sequence-emitting protocol fns sort by author_did: `unsubscribe`(850), `governance_ban_subscriber`(1661), `rotate_all_author_keys`(1740). block_broadcast_subscriber emits a SINGLE KEA leaf (no sort needed). Only 4 KEA emission sites total (unsubscribe_broadcast, block_broadcast_subscriber, execute_revoke, execute_rotate_content_keys) — all counter-correct. reconfigure also split +1/+1.

**Fail-closed split (ADR-011 convergent-governance-trigger→convergent-leaf):** execute_revoke(ban) + execute_rotate_content_keys = FAIL-CLOSED (inline +1 per durable leaf, map_err propagates). unsubscribe + block stay BEST-EFFORT (count successes). Spec §5.14.8 got fail-closed qualifier on ban path + new RotateContentKeys paragraph. Governance paths correctly covered; author-removal(Write) emits NO KEA (block_author only); RestoreAccess/unban emits NO KEA.

**Test seam:** Supervisor::seed_broadcast_author (testing-gated across commands.rs/class_s.rs/handlers/broadcast.rs/supervisor.rs) mirrors seed_peer_pseudonym — legit, never in prod/FFI.

## RESIDUAL GAPS (round-3 findings — verdict INCOMPLETE)

1. **TEST GAP (primary):** Of the 4 explicitly-scoped fixed runtime counter paths, only ROTATE gets a runtime integration test (single+multi-author) — plus reconfigure (also touched). **Ban(execute_revoke), block(block_broadcast_subscriber), unsubscribe(unsubscribe_broadcast) COUNTER arithmetic has NO runtime integration test.** SORT is protocol-unit-tested for ban/unsubscribe/rotate_all, but the §9.9.3-critical checkpoint_events_since bump for ban(1+N)/block(1+kea)/unsubscribe(N) is unasserted. seed_broadcast_author makes multi-author ban/unsubscribe tests trivially writable — should add.

2. **Non-uniform fix pattern (MEDIUM):** PR inlines +1-per-leaf citing mid-loop-drift safety, but leaves 3 structurally-identical fail-closed loops with the OLD post-loop coalesced bump: withdraw_vote(gh.rs:434 `+= event_count`), conflict loops (gh.rs:4085/4414 `+= conflict_event_count`). Conflict loops emit 2 leaves (ConflictDetected+ConflictResolved) → genuine pre-existing drift window on mid-loop `?` failure. Same invariant the PR establishes, applied non-uniformly.

3. **block-path KEA durability unspecified (MEDIUM):** block_broadcast_subscriber KEA best-effort while its companion MemberBlocked is fail-closed — contradicts the code's own "the two leaves are always co-located in the Merkle log" comment (false on KEA-append failure). Spec §5.14 silent on unilateral-block KEA classification (durability para lists KEA *relay message*, not the *event-log leaf*). Arguably correct (unilateral≠convergent-governance-trigger) but needs an explicit decision.

4. **Phantom-provenance doc (LOW):** BroadcastKeyEpochAdvance.timestamp doc (this PR) still asserts "Carried for the relay-message consumer on the per-author block path" — NO prod consumer exists. rotate_broadcast_key (sole producer) has ZERO prod callers (all scp-node/projection + scp-testing sites are #[cfg(test)], discard `_advance`); block path uses rotate_sender_key_for_block + clock.now_secs, never reads this field. Honest "currently unused in production" half contradicts the phantom half.

## Round-4 state (@8818768a9, 8 commits off origin/main) — verdict INCOMPLETE (1 residual)

Round-3 gaps 2/3/4 CLOSED: gap4 timestamp phantom-doc FIXED ("Currently unconsumed — no production wire message or event-log leaf reads this field", honest); gap2 non-uniform pattern DEFERRED to #2243 (withdraw_vote/conflict loops); gap3 block-KEA spec silence DEFERRED to #2244; plus #2245 (ADR-049 D7 convergent-leaf non-atomicity note). All three deferrals legit.

Gap1 (test coverage) PARTIALLY closed: NEW runtime counter tests added for BAN (governance_ban_subscriber_bumps_counter_per_kea, 2 authors → asserts AccessRevoked=1 + KEA=2, delta=3), BLOCK (block_broadcast_subscriber_counter, delta=2 = MemberBlocked+KEA), ROTATE multi-author, RECONFIGURE (+1/+1 split). Sort now has strong protocol tests: unsubscribe/rotate_all/ban all insert reverse-alpha + assert WITHOUT re-sorting. Sort-contract MUST sentence VERBATIM identical across UnsubscribeResult.key_rotations / GovernanceBanResult.rotated_authors / rotate_all_author_keys rustdoc ("Callers that emit event-log leaves from this output MUST preserve this order to maintain §9.9.3 Merkle determinism.").

**SOLE ROUND-4 FINDING (INCOMPLETE, low-risk):** the `unsubscribe_broadcast` RUNTIME path — the ORIGINAL round-2/3 BOTH-bugs site — got its counter fix (inline `+= 1` per durable KEA leaf, broadcast_helpers.rs ~289) but has ZERO runtime test. Its SORT half IS tested (protocol `unsubscribe_key_rotations_sorted_by_author_did`), but the runtime emission+counter is untested while all 4 sibling paths got dedicated runtime tests. `BroadcastCommand::UnsubscribeBroadcast` handler is drivable (handlers/broadcast.rs:80) → a block_broadcast_subscriber_counter-style multi-author unsubscribe test is trivially writable. NOT covered by #2243/#2244/#2245. The asymmetry (4 siblings tested, unsubscribe not) is the tell.

OBSERVATION (not a blocker, documented decision): all counter tests assert `checkpoint_events_since` INDIRECTLY via event_log_entries().len() delta — reconfigure test explicitly states "counter is internal to the actor, verifies indirectly." A counter-only regression (bump line deleted, append kept) would pass. Acceptable: counter is not observable at integration layer (checkpoint_events_since_mut is pub(crate), needs ClassSCell).

LESSON: verify runtime COUNTER-arithmetic tests separately from protocol SORT tests — a sort unit test does not cover the runtime checkpoint bump. When a PR adds sibling tests (ban/block/rotate/reconfigure), enumerate ALL modified emission sites and check each got its own — the un-tested one hides in the symmetry (unsubscribe). Grep `.await?` loops with post-loop `+= count` for the mid-loop-drift anti-pattern.
