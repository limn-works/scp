---
name: adr049-pr6-atomic-read-authority
description: ADR-049 PR-6 atomic read-authority switch — collapse to single Class-M floor registry home; defense assessment
metadata:
  type: project
---

# ADR-049 PR-6 Atomic Read-Authority Switch (commit b61618887)

Collapsed sender-key epoch + recv-sequence anti-replay floors to ONE authoritative
home: the Supervisor-owned Class-M `ContextFloors` registry (`supervisor/floors.rs`).
Provider mirrors (`SenderKeyStore.epochs` reads on node, `recv_sequence_tracker` field,
`export_*`/`validate_and_merge_*` twins) DELETED.

## Secure-by-construction (verified sound)
- **Gate primitives** (`check_and_advance_sender_epoch`/`_recv_sequence`, floors.rs): single
  `self.floors.entry(*ctx).or_default()` guard spans read→reject-`<=`→reject-overshoot→write.
  TOCTOU-atomic by construction (no get-then-insert). `validate_and_merge_*` two-pass
  validate-before-apply under one guard = atomic (no partial apply).
- **3 seams fail-closed via `?`** (messaging_helpers decrypt_and_dispatch + mirror_forward).
  Seam2 = gate-BEFORE-install: process_incoming_sender_key returns (key,epoch) w/o install →
  check_and_advance(epoch)? → set_sender_key_unchecked(key). Reject `?`s before install.
- **Provider twins DELETED = compiler is primary G2 enforcement.** `deps.crypto.export_*` /
  `deps.crypto.validate_and_merge_*` won't compile. Structural assertion is belt-and-suspenders.
- **D2 sink**: restore merges blob(incoming)→live registry; guard on `incoming.is_empty()`
  (NOT live) so cold restart (empty registry, non-empty blob) POPULATES → replay rejected.
- **Only ONE prod remote-key install path** (seam2, gated). `store_member_sender_key` (ungated)
  has ZERO prod callers. distribute/restore set_unchecked are local/restore (fine).
- **Defense-in-depth NOT lost**: MLS ratchet replay protection is the independent PRIMARY layer
  beneath the sender-key floor (provider.rs:154 comment). Single floor home ≠ single point of failure.

## Findings
- **P1 (detection gap) — ✅ RESOLVED @d02680cd9** (pipeline_wiring.rs:1141). Assertion now (a) requires
  `check_and_advance_sender_epoch` present in decrypt_and_dispatch (line 1169); (b) asserts gate-BEFORE-install
  ordering via `extract_fn_body(...).find(gate) < .find(install)` (lines 1174-1185) — `extract_fn_body` runs
  `clean_and_extract_braced` which strips comments/strings/char-literals (blanks preserving offsets) so the
  index comparison is comment/string-AWARE and reflects real code positions (verified real src: gate
  messaging_helpers.rs:2979 < install :2986, both `?`-propagated). Also added mirror_forward gate assertion.
  Redundant compiler-enforced NEGATIVE (`deps.crypto.export_*`/`validate_and_merge_*`) trimmed — provider twins
  DELETED so those won't compile (comment explains, simplifier-E compliant). Restore assertion retargeted to
  `validate_and_merge_all_floors` in `restore_crypto_state_with_floor_guard` (real src lifecycle_helpers.rs:1826).
  Assertion set is positive fail-closed-SHAPE + ordering (sound + bounded), not a denylist.
  RESIDUAL (P2, inherent to text-structural tests): presence+ordering proves gate is CALLED before install, NOT
  that its Result is PROPAGATED (`?`) vs swallowed (`let _ =`/`if let Ok`). A regression keeping call+ordering but
  dropping `?` would PASS. The two negative `!fn_body_contains(...,"non-fatal[...]")` checks (lines 1188, 1205)
  were meant to guard the log-and-drop spelling but are NEAR-VACUOUS: fn_body_contains uses the cleaned body, so
  "non-fatal" as a comment or log-message string is stripped and never matched — they can only catch it as a live
  code identifier (won't happen). Compensating layers: F-3 debug_assert at recv seam + behavioral regression tests
  (BUG-1 atomic-reject, cold-restart durability). Acceptable defense-in-depth; do NOT grow the negative into a
  denylist (non-convergent).
- **P2**: G2 negative assertion covers only 3 of 6 export-caller files (MANAGER/SUPERVISOR/LIFECYCLE_HANDLER);
  broadcast_helpers, trust_recovery_helpers, ttl_close_helpers unguarded. Belt-and-suspenders only (compiler primary).
- **P2 (accepted divergence)**: member-granular prune (no D3 whole-membership sweep). Fail-safe (over-reject only).
  Residual liveness edge: in-flight key-dist from just-removed member re-populates sender_epochs[did] via seam2;
  a later FRESH rejoin at lower epoch would be wedged until re-rotation above lingering floor. Bounded, self-heals.
- **Liveness (bounded, self-healing)**: actor crash in seam2 gate→install window leaves floor=N but key-N
  uninstallable (re-dist rejected as non-monotonic). Loses that sender's epoch-N traffic until sender's NEXT
  rotation (N+1 installs). Never fail-open. Matches plan's "fail-safe-liveness".

## Browser/node split (coherent boundary, no gap)
Browser (WASM scp-client, ADR-034/057) keeps own independent floors (SenderKeyStore.epochs + own recv tracker
in snapshot.rs). Node registry authoritative for node. Floors are per-RECEIVER, not shared state. Each endpoint
gates its own recv path. Only shared thing = scp-protocol SenderKeyStore epoch TYPE API, not mutable state.
