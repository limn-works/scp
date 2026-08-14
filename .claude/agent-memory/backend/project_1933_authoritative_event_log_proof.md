---
name: project-1933-authoritative-event-log-proof
description: "#1933 event_log_verify fix — one authoritative snapshot per call; why a commitment-probe + separate proof call is unsound; check-*.sh need CARGO_TARGET_DIR too"
metadata:
  type: project
---

`event_log_verify` (all 3 bridges) now derives every Merkle answer from ONE
`Supervisor::authoritative_event_log(ctx)` snapshot, delegating to the
pre-existing `ContextEventLogProvider::rebuild_event_log_for_proof`. Landed on
`fix/1933-f3-event-log-verify-authoritative-tree` (commit `001c38544`).

**Why:** proofs ran over the per-context UCAN-state log (bridge-local,
near-empty, caller-influenceable leaves), so any *absence* claim for a real
authoritative event returned `verified: true` — a forgeable false negative.
NAPI additionally failed OPEN via `.ok().and_then(|s| ....ok().flatten())`.

**How to apply — two traps to avoid on any future proof work here:**

1. **Never build a second Merkle tree.** `rebuild_event_log_for_proof` is
   documented as "the proof seam … so there is no second tree to keep in sync."
   An earlier attempt at this fix (`6394dde51`, dropped) added one and was
   discarded — it recreates the exact divergence class the bug *is*.
2. **Never assemble an answer from two replays.** A first draft used
   `event_log_commitment()` as a reachability probe *and* as the source of
   `leaf_count`, then called `prove_event_inclusion()` separately. Two replays
   straddling a concurrent `append_event` describe different trees, so the
   reported `root` and `leaf_count` pin nothing — and the `debug_assert_eq!`
   guarding their equality could panic in debug builds on a benign race.
   Returning the *snapshot* instead collapses probe + commitment + proof into
   one replay, makes consistency hold by construction, and gives the
   fail-closed vs. claim-is-false split for free (snapshot error = `SCP-CTX-2138`
   "cannot answer"; any later proof error = honest `CTX_2025`).

`SCP-CTX-2138` = authoritative log unreachable (suspended/shut down via
`check_ready`, no supervisor, or provider `None`). Provider `None` means
UNKNOWN, never empty — empty-but-live is `Ok(Some(vec![]))`.

**Gotcha:** `scripts/check-pure-helpers.sh` runs bare `cargo test` with no
target-dir override, so it hits the poisoned shared target and fails with
bogus errors about unrelated symbols (`ContextError::Outlet`,
`OutletContextNotActive`). Export `CARGO_TARGET_DIR=<isolated>` before running
the check scripts, not just before clippy/nextest. See
[[feedback-worktree-absolute-path]].
