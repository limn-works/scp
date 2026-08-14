---
name: adr049-pr6-atomic-read-authority
description: Red-team assessment of ADR-049 PR-6 (branch feat/adr049-pr6-atomic-read-authority-switch, commit b61618887) — provider floor mirrors deleted, Supervisor registry is sole authority. D1/D2 chains.
metadata:
  type: project
---

# ADR-049 PR-6 Atomic Read-Authority Switch (commit b61618887)

Provider anti-replay gate deleted; Supervisor `ContextFloors` registry (floors.rs)
is sole floor home. 3 recv/send seams fail-closed via `check_and_advance_*(..)?`;
restore merges blob→registry via `validate_and_merge_*`.

## What HOLDS (D1/D2 defeated)
- **Single receive path**: only `decrypt_and_dispatch` (messaging_helpers.rs:2932)
  calls `crypto.open()`, and it gates recv via `check_and_advance_recv_sequence(?)`
  before surfacing OpenedEnvelope. No alternate open() path.
- **Gate-before-install** at Management seam (messaging_helpers.rs:2977-2987):
  `process_incoming_sender_key` (HPKE+DID auth, no install) → `check_and_advance_sender_epoch(?)`
  → `set_sender_key_unchecked`. Rolled-back epoch rejected, key never installed. D1 defeated.
- **Restore couples crypto-install to floor-merge**: only prod caller of bare
  `restore_crypto_state` is inside `restore_crypto_state_with_floor_guard`
  (lifecycle_helpers.rs:1793). Merge runs synchronously (no yield) before actor
  processes mailbox. Cold restart cannot decrypt without registry populated. D2 defeated.
- **Merge guards on `incoming.is_empty()`** (floors.rs:438/547) NOT local — cold
  restart (empty registry, non-empty blob) RUNS the merge. Legacy snapshots seed a
  floor via `legacy_floor = sender_key_epoch.max(1)` (provider.rs:2547).
- All 6 export sites source `deps.supervisor.export_*` (G2 clean, zero `crypto.export_*`).
- All 6 remove seams pair `remove_member_sender_key` + `remove_member_floors`.
- TOCTOU-safe single `entry()` guard on every gate/merge.

## OPEN FINDING — RED-P6-01 (MEDIUM, availability / attacker-accelerable DoS)
**Cold-restart restore of a >1000-epoch context FAILS** — a regression introduced
by the read-authority switch.
- `validate_and_merge_epoch_floors` (floors.rs) computes overshoot
  `ceiling = local.saturating_add(max_advance)` where `local = sender_epochs[did]
  unwrap_or(0)`. On COLD restart local=0 → ceiling=1000. Any incoming per-sender
  floor >1000 → `SenderEpochOvershoot` → whole merge rejected → restore aborts
  (CryptoFailed, rollback). Every subsequent restart re-reads the same blob and
  re-fails → **context permanently unrestorable**.
- OLD path (`SenderKeyStore::restore_epoch_high_water`, scp-protocol mod.rs:431)
  inserts UNCONDITIONALLY (no overshoot gate) → old provider-authoritative flow
  restored high-epoch contexts fine. New sole sink regresses this.
- Reachable naturally: any long-lived context with >1000 cumulative sender-key
  rotations (each rotate = +1). Cold-restart test (supervisor.rs:18383) uses
  epoch=4 → does NOT catch it.
- **Attacker-accelerated**: a malicious member advances their own `sender_epochs`
  floor by up to +1000 per key-distribution Management message (live gate ceiling
  = current+1000). 2 messages: 0→1000→2000. Victim's snapshot persists (attacker,2000).
  Victim's next COLD restart: 2000>1000 → restore bricked. Persistent DoS.
- Fail-SAFE re replay (rejects, never admits) but breaks D2 availability.
- Fix candidate: under MaxMergeTrustedLocal (trusted self-snapshot) the poisoning
  ceiling should NOT gate against local=0 — the accumulated high-water is
  authoritative, not a single advance step. The `local+MAX_EPOCH_ADVANCE` ceiling
  is a per-step-advance bound misapplied to a cumulative floor on cold restart.

## Accepted / out-of-scope
- Crafted at-rest snapshot lowering floors under trusted_local=true: accepted
  trust model (self-snapshot integrity), pre-existing, documented.
- D3 whole-membership sweep divergence: orchestrator-accepted, fail-safe (over-reject).
- debug_assert_ne local_did!=remote at recv seam: compiled out in release, but
  structurally prevented + fail-safe. Not a hole.
