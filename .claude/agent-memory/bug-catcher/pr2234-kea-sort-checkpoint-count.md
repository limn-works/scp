---
name: pr2234-kea-sort-checkpoint-count
description: PR #2234 (39a19e90c) fast-follow to #2218 — ban-path KEA sort + reconfigure checkpoint-count split. CLEAN.
metadata:
  type: project
---

# PR #2234 `fix/rotate-content-keys-review-followup` — CLEAN (0 actionable bugs)

**Trap avoided:** `main...branch` 3-dot diff is ~3.6k+2.1k lines of UNMERGED baseline
(ADR-049 PR-7 crypto-move, ADR-062 slices, #2218). The REAL PR is a single commit
`39a19e90c` (148 insertions, 5 files). Always `git log --oneline main..branch` to find
the actual commit before reviewing — merge-base here is `3c1683116` (very stale).

**The 2 fixes (both correct):**
1. HIGH bug1 fix: `governance_ban_subscriber` (broadcast/mod.rs:1651) now
   `rotated_authors.sort_unstable_by(|a,b| a.author_did.cmp(&b.author_did))` before
   returning. Mirrors the `rotate_all_author_keys` sort. author_did is String (byte-lex,
   process-stable). Only consumers of rotated_authors are iter + `.len()` (no `[i]` index
   access anywhere) → sort breaks nothing, only fixes Merkle-leaf determinism (§9.9.3).
2. MEDIUM bug2 fix: `execute_reconfigure_governance` (governance_helpers.rs:3354) adds a
   FIRST `*cell.class_c_view().checkpoint_events_since_mut() += 1;` right after the
   GovernanceReconfigured `?`-append, keeping the existing `+= 1` after the
   GovernanceDeadlockRecovery `?`-append. PARENT (363028aaa) had ONLY the trailing `+= 1`
   → under-counted by exactly 1 (two durable leaves, one bump) on EVERY happy path. Split
   → += 2 on success, += 1 if 2nd append fails (matches durable-leaf count). Counter is a
   live in-memory Class-C mutation (not transactional) so it survives an Err return and
   rides the next coalesce persist — the fix relies on that (sound). No view held across
   `.await` (each `class_c_view()` is a statement-scoped temporary).

**Verified sound (the task's checklist):**
- advances pushed POST-mutation (`author.epoch += 1` then push `new_epoch: author.epoch`).
- `old_epoch = new_epoch.saturating_sub(1)` never underflows: both `governance_ban_subscriber`
  and `rotate_all_author_keys` set new_epoch via `checked_add(1)`/`+=1` so new_epoch ≥ 1 always.
  saturating_sub is exact, not lossy.
- `kea_success_count: u64` overflow impossible (bounded by author count).
- 0 rotated_authors → `+= 1 + 0` correct (AccessRevoked leaf only).
- `*cell.class_c_view().checkpoint_events_since_mut() += 1 + kea_success_count` is ONE
  class_c_view() call (statement temporary), no double-borrow — compiles.
- drain `view.mode_mut().crypto_mut()` — view is block-local, alive across await, fine.
- `GovernanceDeadlockRecoveryPayload.missed_windows` now `.map(|(d,n)| (d.0.clone(), *n))`
  carrying real per-DID counts — the OLD #1847 `.len()` bug (see eventlog-1847 memory) is
  FIXED on this baseline. Payload type `Vec<(String,u32)>`, justification `Vec<(DID,u32)>`.

**LOW (non-actionable):** the two new sort tests add 3 authors in reverse-insertion order
and assert sorted WITHOUT re-sort. Default HashMap RandomState is per-instance-seeded, so a
missing-sort regression is caught only ~5/6 of runs (not deterministic) — weak-but-repeated
CI guard. Not a production bug. Did NOT run the tests (working tree on detached main; branch
tests need checkout + testing feature + DYLD_LIBRARY_PATH) — logic verified by reading.
