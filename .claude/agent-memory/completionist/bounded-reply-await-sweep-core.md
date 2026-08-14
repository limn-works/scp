---
name: bounded-reply-await-sweep-core
description: Audit of reply-await-sweep-core branch @c33e7ee35 (centralize bounded_reply_await helper + sweep supervisor.rs/recovery.rs/handle.rs) — found 2 missed genuine reply-await sites
metadata:
  type: project
---

# bounded_reply_await core sweep audit (branch reply-await-sweep-core @c33e7ee35)

Follow-on to [[bounded-reply-await-130]]. Extracts a shared `pub(crate) async fn bounded_reply_await<T>(rx) -> Result<T, BoundedReplyError{Dropped,Elapsed}>` into `context/actor/handle.rs` (mechanics only: `timeout(REPLY_TIMEOUT, rx)` + classify; each caller keeps its own disposition). Exported `pub(crate)` from `context/actor/mod.rs` — correct, because `identity::recovery` is a SIBLING of `crate::context` (`pub(in crate::context)` would be unreachable). Helper has real callers + 3 real behavioral tests (elapsed / dropped / passthrough). No stubs/TODO/dead code. handle.rs sweep now COMPLETE — all 3 sites bounded incl. the previously-missed `dispatch_recovery_send_notification` (the #130 gap, now closed). recovery.rs (1) done.

**Finding (INCOMPLETE)**: supervisor.rs sweep migrated 57 sites but MISSED 2 genuine reply-awaits, both pre-existing on main (untouched, NOT in diff):
- `reserve_outlet_economy_via_actor` @ supervisor.rs:11850 — bare `reply_rx.await.map_err(..)?` after `dispatch_outlets_command`. Live caller @12338 (outlet invoke path).
- `reserve_outlet_stream_economy_via_actor` @ supervisor.rs:11898 — same. Live callers @12590 (stream open) + @30993 (test).

Both dispatch Phase-1 economy reserves (`ReserveOutletEconomy` / `ReserveOutletStreamEconomy`) through `dispatch_outlets_command` — the SAME wedgeable per-context actor mailbox as the 6+ migrated siblings (`outlet_stream_reserve_grant`, `settle_outlet_economy_via_actor`, `settle_outlet_stream_via_actor`, `reconcile_stream_reservations_via_actor`, `reverse_stream_escrow_via_actor`). Docstring even says "the reserve runs inside the per-context actor." Same wedge class, no legitimate exclusion → a wedged actor pins these callers forever, the exact bug the sweep exists to close. One-line fix each (wrap in `bounded_reply_await`).

**Exclusions verified CORRECT**: (a) 7 test `.expect` sites in `mod tests` (>15827): 19525,19550,20355,21033,21901,23300,32292 — untouched ✓. (b) saga phase dispatch (`dispatch_prepare_phase`/`dispatch_commit_phase` ~8666-8956) bounds the WHOLE dispatch future with distinct `PHASE_TIMEOUT` (30s/phase), not a raw reply oneshot — different class, correctly left ✓. (c) second-tier `handlers/saga.rs`+adapters deferred = honest scope split (branch touches only 5 files, none is saga.rs). (d) test-only `timeout(5s, summary_rx)` @30613/30857 in tests — not REPLY_TIMEOUT reply-awaits ✓.

**Definitive scan** (production region <15827, after `git show <rev>:file`): only bare receiver-alone-on-line awaits are 11850 & 11898; only inline `rx.await` hit is 15162 (a doc comment). Every other `(tx,rx)` oneshot routes through `bounded_reply_await`.

**Lesson (reinforces #130)**: a centralize-and-sweep of "all reply-awaits in file Y" must grep Y for EVERY `oneshot::channel` creation and trace each receiver's await — not just the ones the coder remembered. Enumerate all `oneshot::channel` sites, split test/prod at the `mod tests` line, then verify each prod receiver is `bounded_reply_await(rx)`. 57 of 59 is a gap.
