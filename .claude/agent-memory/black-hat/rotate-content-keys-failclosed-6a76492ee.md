---
name: rotate-content-keys-failclosed-6a76492ee
description: 3-pass review of KEA fail-closed + inline-counter PR (branch fix/rotate-content-keys-review-followup) — governance KEA leaves fail-closed, unsubscribe best-effort, inline per-leaf counter bump
metadata:
  type: project
---

# KEA fail-closed + inline counter (branch fix/rotate-content-keys-review-followup)

## Pass 3 (FINAL, @2fd43bee9 — commits after 6a76492ee: 9691cbc10 inline-counter, b585006b6 block counter, 29e816264 softened comment, cf51c47cd seed-seam+test, 2fd43bee9 spec)

### Verdict: SHIP. No CRITICAL/HIGH/security. Production counter code is CORRECT and IMPROVED.

- **Inline `+= 1` per durable leaf** (execute_revoke, execute_rotate_content_keys, execute_reconfigure_governance) replaces old coalesced `+= 1 + kea_success_count`. This FIXES prior pass-2 finding #2 (under-count on partial fail): each durable leaf now gets its bump immediately, so a mid-loop Err leaves the counter EXACTLY reflecting durable leaves. Robust across retries (each durable leaf = one bump, even on double-append). No double-count, no miss. AccessRevoked/ContentKeysRotated bumped once after their `.await?`; KEA per-iteration after each `.await?`. Non-broadcast path: rotated_authors empty → just the AccessRevoked +1 (same as before). H7 sender-key rotation emits NO event-log leaf → correctly no bump.
- **unsubscribe** (best-effort KEA): MemberLeft leaf fail-closed `+=1` inline; KEA loop tracks kea_success_count, post-loop `+= kea_success_count`. Post-loop safe because best-effort never early-returns. Correct.
- **block_broadcast_subscriber**: `+= 1 + kea_appended` (MemberBlocked fail-closed + KEA best-effort success flag). Correct.
- **Spec §5.14.8** now HONEST (no phantom provenance): ban clause 4 + new RotateContentKeys clause both say "fail-closed per ADR-011 (convergent governance trigger→convergent leaf)"; unsubscribe stays "authorization-UPWARD-safe...coalesced(best-effort)". Matches code exactly.
- **Sorts** load-bearing + deterministic: rotate_all_author_keys / governance_ban_subscriber sort_unstable_by author_did (unique HashMap keys = total order); emission iterates the sorted Vec so leaf order = sorted. Every replica sorts identical canonical DIDs → same Merkle root. Cannot be defeated.
- **seed_broadcast_author test seam** AIRTIGHT: all 5 sites (commands variant, handler, class_s view method pub(crate), supervisor method, 2 routing arms) `#[cfg(feature="testing")]`. Never prod, never FFI. Standing-dispatch arm returns ContextNotRegistered.

### FINDINGS
- **MEDIUM (test-quality, 3rd recurrence of PR#2218 pattern).** New `rotate_content_keys_counter_multi_author` (governance_integration.rs:3243) added specifically to "directly pin the inline counter-bump arithmetic" (commit msg) does NOT read `checkpoint_events_since`. It asserts LEAF counts (`entries.len() - baseline == 1 + num_authors`). Leaf emission and counter bumps are INDEPENDENT statements → reverting the inline `+= 1` bumps (the PR's core change) leaves leaves intact and PASSES. NO unit test asserts the counter for execute_revoke/execute_rotate_content_keys. Counter IS unit-observable in-crate (class_s.rs asserts `cell.checkpoint_events_since`), so a real guard is feasible (integration crate can't reach it — no ContextManager accessor). Headline regression guard is illusory. NOT security (counter drift = §9.9.3 cadence only; build_checkpoint derives event_count from real event_log_entries().len(), Merkle root always correct).
- **LOW (liveness, pre-existing widened).** Fail-closed KEA under PERSISTENT event-log failure → governance proposal Err → executed_proposals rollback → retry re-runs governance_ban_subscriber/rotate_all_author_keys → double epoch advance + duplicate AccessRevoked/ContentKeysRotated durable leaves + KEA chain gap (N→N+1 never recorded for the author whose leaf failed, only N+1→N+2). Bounded (2^64), local-storage-only (NOT remotely triggerable — attacker can't selectively fail one append without owning the node), self-inflicted idempotency damage, not a confidentiality/integrity break. Comment softened in 29e816264 (no longer overstates retry cleanliness) — prior pass-2 #1 addressed.

## Pass 2 (@6a76492ee) — superseded by above; asymmetry rationale (self-action best-effort vs convergent fail-closed) still valid. Original findings #2 FIXED by inline counter; #1 comment softened; #3 (no fail-injection test for headline Err-propagation) STILL OPEN (no backend to inject append failure); #4 == the MEDIUM above.
