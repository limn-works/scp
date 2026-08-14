---
name: pr-rotate-content-keys-followup-6a76492ee
description: Fail-closed KEA loop conversion regressed checkpoint counter exactness on the event-log append-failure path in execute_revoke + execute_rotate_content_keys
metadata:
  type: project
---

# fix/rotate-content-keys-review-followup @6a76492ee (2nd pass)

**Finding (MEDIUM):** `governance_helpers.rs` `execute_revoke` (~L1012) and `execute_rotate_content_keys` (~L3207) convert KEA loops to fail-closed (`?`) but keep a single POST-loop counter bump `+= 1 + rotated_authors.len()` / `+= 1 + key_advances.len()`. Comment claims "All-or-nothing (fail-closed) so the count is exact" — FALSE. Event log is append-only; `.await?` leaves are individually durable and NOT rolled back on Err. If the loop fails on KEA[k], AccessRevoked/ContentKeysRotated + KEA[0..k] are durable but the tail bump never runs → `checkpoint_events_since` under-counts → §9.9.3 checkpoint-position drift (the exact invariant the code claims to protect).

**Why it's a regression:** OLD code `+= 1 + kea_success_count` was EXACT because best-effort loop never early-returned (tail bump always ran). Fail-closed conversion is incompatible with a tail bump.

**Decisive evidence — same file, correct pattern:** `execute_reconfigure_governance` (L3300-3341, PR #2234) bumps `+= 1` IMMEDIATELY after each durable leaf, commenting exactly why (a later append failure must not under-count). `unsubscribe_broadcast` in THIS SAME commit correctly keeps `kea_success_count` (stayed best-effort). So commit ships right pattern in 2 places, wrong in 2.

**Fix:** per-leaf `+= 1` immediately after each successful append; delete both post-loop `+= 1 + len` lines. Mirror reconfigure.

**Trap in the task framing:** "loop fails partway → returns Err, += never reached, correct since operation failed" — WRONG. Operation is NOT rolled back; leading leaves are durable. Not-bumping under-counts them.

**Verified CLEAN:** unsubscribe kea_success_count (`+=0` when rotate_keys false, no double-count); sort test uses subscribe_open + reverse-insert authors, asserts ascending no re-sort; reconfigure test reads baseline BEFORE, delta=3 correct (1 GovernanceActionExecuted lifecycle leaf — propose appends NO durable ProposalCreated leaf — + Reconfigured + DeadlockRecovery); `len() as u64` widening, no truncation.
