---
name: rotate-content-keys-failclosed-pass4-2234
description: 4th-pass black-hat verdict on PR#2234 fix/rotate-content-keys-review-followup — KEA fail-closed + inline counter + seed seam
metadata:
  type: project
---

# PR#2234 rotate-content-keys review-followup — PASS 4 (final)

Verdict: PASS. No new exploitable attack surface introduced by the fixes.

**Counter accounting now CORRECT in all 5 modified fns and actually FIXES 2 pre-existing under-counts:**
- block_broadcast_subscriber (broadcast_helpers.rs): origin/main appended 2 leaves (MemberBlocked+KEA) but bumped counter only +1 at end → UNDER-COUNT. Now +1 after fail-closed MemberBlocked, +1 after durable KEA. Correct.
- execute_reconfigure_governance (governance_helpers.rs): origin/main appended 2 leaves (GovernanceReconfigured+GovernanceDeadlockRecovery) with single trailing +1 → UNDER-COUNT. PR added inline +1 after first leaf → 2 bumps/2 leaves. Correct.
- execute_revoke / execute_rotate_content_keys: KEA loop converted best-effort→fail-closed (`?`); +1 after AccessRevoked/ContentKeysRotated, +1 per durable KEA. Correct.
- unsubscribe_broadcast: best-effort KEA, +1 only on durable append. Correct (no over-count).

**LINCHPIN (why fail-closed counter is durable):** all governance mutation handlers use `Outcome::err_mutated` (not `err`) on error — governance.rs handle_execute_governance_action_actor:706, propose/propose-checked/vote/approve all err_mutated. So the in-memory `checkpoint_events_since` bump survives the Err return → counter matches durable leaves on partial-fail. If any of these were plain `Outcome::err`, KEA-append-fail would discard the counter bump while leaves stay durable → §9.9.3 drift. They are NOT.

**Fail-closed conversion is fail-SAFE not exploitable:** on KEA-append-fail, ban/rotation STATE already durable (committed inside commit_class_s_keep BEFORE loop) + executed_proposals replay marker durable → no retry/double-rotate. Caller sees Err but action applied. Only trailing KEA audit leaves for authors k..N missing (epoch advanced, leaf absent) — identical divergence to old best-effort; fail-closed just surfaces it as error (ADR-011 convergence-integrity intent). Accepted tradeoff.

**seed_broadcast_author test seam:** #[cfg(feature="testing")] at ALL 4 layers (commands.rs BroadcastCommand::SeedBroadcastAuthor, handlers/broadcast.rs, class_s.rs ClassCMut method, supervisor.rs method). Standing/shim path returns ContextNotRegistered. Mirrors accepted SeedPeerPseudonym precedent exactly. Adds legitimate author-registry state (same as governance author-add). No prod reachability, no new export class.

**Sort determinism:** sort_unstable_by author_did at 3 sites (unsubscribe, governance_ban_subscriber, rotate_all_author_keys). author_dids unique (add_author rejects dup) → unstable OK. Tests assert order WITHOUT re-sorting.

**FINDING (LOW-MEDIUM, recurring — same as PR#2218/6a76492ee):** new counter tests in governance_integration.rs (rotate_content_keys_counter_multi_author, execute_revoke_*, block_broadcast_subscriber_counter) assert EVENT-LOG LEAF COUNTS via event_log_entries() as a PROXY, NOT the actual `checkpoint_events_since` field. Reverting the inline `+= 1` bumps would NOT fail these tests. Counter IS unit-observable (state.rs pub; precedents messaging_helpers.rs:3878, class_s.rs:6733) but not exposed on manager API for integration tests. Security-relevant property (durable leaves) IS tested; unguarded property is §9.9.3 cadence-drift only. Non-blocking.
