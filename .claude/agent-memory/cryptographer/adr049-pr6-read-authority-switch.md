---
name: adr049-pr6-read-authority-switch
description: ADR-049 PR-6 atomic read-authority switch (commit b61618887) — Supervisor floor registry becomes authoritative Class-M home for sender-key epoch + recv-sequence anti-replay floors; provider mirrors deleted. Crypto review verdict + the one cold-restart ceiling regression.
metadata:
  type: project
---

# ADR-049 PR-6 read-authority switch (commit b61618887)

Flip: Supervisor `ContextFloors` registry (`supervisor/floors.rs`) becomes the sole authoritative
home for per-sender sender-key epoch high-water (`sender_epochs`) + recv-side `(epoch,sequence)`
anti-replay floors (`recv_sequence`). Provider mirrors (`recv_sequence_tracker`, provider
`export_*`/`validate_and_merge_*` twins, open() H9/replay/tracker block) DELETED.

## Verified SOUND (items 1,2,4,5 of the crypto charge)
- **Anti-replay preserved (item1):** registry `check_and_advance_recv_sequence` rejects `next<=current`
  lexicographically; `ReceiveFloor{epoch,sequence}` derived Ord is epoch-major (epoch declared before
  sequence, builder.rs:33) = byte-identical to deleted provider `epoch<last||(epoch==last&&seq<=last_seq)`.
  (epoch,sequence) are AAD-bound in `decrypt_sender_layer` → replay can't relabel to a higher floor.
  Gate `?` fires BEFORE dispatch in `decrypt_and_dispatch`. Deploy-time swap, no live transition window;
  registry self-populates via seams + restore.
- **Epoch monotonicity + poisoning (item2):** seam2 order = `process_incoming_sender_key`(HPKE-open+DID-auth,
  returns (key,epoch), NO install/gate) → `check_and_advance_sender_epoch(epoch)?` (rejects `epoch<=current`
  AND `epoch>current+1000`, atomic single-entry guard) → `set_sender_key_unchecked`. Poisoned epoch → `?` →
  key never installed. Equivalent-or-stronger than deleted H9. Only remote install path in prod is seam2
  (gated). distribute_sender_key set_unchecked = LOCAL self key (legit). open() = pure decrypt + receive_floor.
- **F-2/F-3 (item4):** gate-before-install ordering sound (epoch advanced before key installed; recv decrypts
  only if key installed → floor≥N → recv ceiling never stale). F-3 `debug_assert_ne!(sender_did,local_did)`
  at recv seam; co-mingling of local scalar into sender_epochs is fail-safe re REPLAYS (independent recv
  monotonic floor blocks replays regardless of co-mingled ceiling); precondition genuinely holds (never
  receive own sender-key app msgs). NOTE: doc says co-mingling "over-reject" but ceiling axis could over-PERMIT;
  harmless — can't decrypt at an epoch whose key isn't installed. Minor doc imprecision only.
- **Merge direction (item5):** restore passes incoming=blob(restored.sender_epochs), local=live registry.
  Matches deleted provider twin NET semantics exactly (old: base=captured-live `local_floors`, incoming=snapshot
  read-from-store post-restore; reject snapshot<live under RejectRegression). Empty-guard correctly flipped from
  provider's `local_floors.is_empty()` to registry `incoming.is_empty()` (floors.rs:449/551) — REQUIRED because
  new restore_crypto_state no longer installs floors directly (returns RestoredFloors), so merge is the SOLE
  population path on cold restart.

## CONFIRMED FINDING — cold-restart overshoot-ceiling availability regression (fail-closed, NOT a replay hole)
- On COLD restart (process restart → `restore_all_contexts`, lifecycle_helpers.rs:2825, trusted_local=true),
  the Supervisor registry starts EMPTY. `restore_crypto_state_with_floor_guard` now routes the blob's per-sender
  epoch floors through `validate_and_merge_epoch_floors`, whose overshoot ceiling is enforced under BOTH policies:
  `ceiling = local(0) + MAX_EPOCH_ADVANCE(1000)`. A snapshot whose per-sender (or local-scalar) sender-key epoch
  high-water EXCEEDS 1000 → `SenderEpochOvershoot` → restore rejected via `?` → context fails to restore (bricked
  every restart).
- OLD behavior (origin/main): cold restart SHORT-CIRCUITED the provider merge (`local_floors.is_empty()`) and
  `restore_crypto_state` loaded floors verbatim via `restore_epoch_high_water` — NO ceiling, unbounded. Old code
  comment explicitly argued "nothing to ceiling against; snapshot floors load verbatim; NOT a security regression."
- So the empty-guard flip (the D2 fix) UNINTENDEDLY removed the cold-restart ceiling bypass. Fail-CLOSED
  (over-rejects, never admits replay) so NOT a security break, but an availability/durability regression for
  long-lived/high-churn contexts (>1000 sender-key rotations per sender). Plan's D2 req only covered the LOWER
  (legacy back-compat) bound, never the ceiling×cold-restart interaction. Cold-restart test uses epoch 4 → misses it.
  Recommend: on trusted_local cold restart (empty baseline) either bypass the ceiling (mirror old semantics) or
  seed baseline from the blob before ceiling-checking. Flag for human.

## RE-REVIEW @ d02680cd9 — Finding-1 FIXED + cross-axis atomicity (A2 + A). VERDICT: BOTH SOUND, no findings.
- **A2 fix**: overshoot ceiling in the MERGE now gated `if policy == RejectRegression` (floors.rs 715-724 epoch, 739-751 recv). Under MaxMergeTrustedLocal ALL validation skipped → straight to monotone-max apply → high-water loads verbatim (fixes Finding-1: 5000>1000 restore). ADR-049:239 spec UPDATED to match (ceiling untrusted-only). Does A2 reopen poisoning ANYWHERE? **NO.** (1) LIVE gates check_and_advance_* take NO MergePolicy → ceiling saturating_add UNCONDITIONAL (279-286/351-359); live seams messaging_helpers 2956/2979 pass MAX_EPOCH_ADVANCE=1000, u64::MAX remote advance → reject → set_sender_key_unchecked(2986) never reached. (2) MaxMergeTrustedLocal set ONLY at lifecycle_helpers:2821 (restore_context, trusted_local=true) reachable ONLY from RestoreContext dispatch (supervisor 3005)/watchdog respawn_from_snapshot(4544)/process-restart — ALL read durable local persistence via load_persisted_context_state, NEVER a network/caller blob. All 3 import callers (2124, 2138, lifecycle_control:142) pass false→RejectRegression→ceiling ON. (3) untrusted overshoot still rejected (test supervisor 18540). (4) verbatim trusted load safe: own at-rest snapshot in trust model; every advance was live-gate-ceilinged; AND apply is monotone-MAX vs live registry so trusted-local CANNOT lower a live floor, a raised floor is fail-safe (over-reject/DoS, never replay).
- **A (cross-axis atomicity)**: validate_and_merge_all_floors (floors 675-770) validates BOTH axes no-mutation then applies BOTH; first-fail early-return → registry UNTOUCHED. Recv epoch-ceiling reads PROJECTED post-apply baseline = local.max(incoming_epoch_max[did]) (688-699/740-743) = exact parity w/ sequential epoch-then-recv. Empty-guard on INCOMING sets (684) preserves cold-restart D2. Single-axis twins now #[allow(dead_code)] unit-test-only; prod uses only combined sink. Tests: floors 1465 cross-axis-atomic, supervisor 18686 recv-regress-leaves-epoch-unchanged, 18612 cold-restart-high-epoch-verbatim (Finding-1 regression guard). 26 floor unit + 3 A2 supervisor tests PASS. Benign: entry().or_default() on rejected merge leaves empty ContextFloors entry = absent-equivalent, not partial apply.
