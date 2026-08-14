---
name: adr049-pr7-atomic-core
description: Attack surfaces in ADR-049 PR-7 ATOMIC CORE crypto-ownership move (provider DashMap -> actor-owned state). Nonce-reuse and double-owner seams.
metadata:
  type: project
---

# ADR-049 PR-7 ATOMIC CORE (SCP-CRYPTOMOVE-001) — attack surfaces

Reviewed against origin/main c34387059+ (Preps A-E). PR-7 wires the FIRST production
`take_crypto_state` caller — all seams are new. Provider crypto lives in
`crates/scp-runtime/src/crypto/mls/provider.rs`; actor state in
`crates/scp-runtime/src/context/actor/state.rs`.

## CRITICAL findings the plan does NOT fully close
- **CM-001 Double-owner via create-after-take.** `create_group_into_slot` (provider.rs:~908)
  and `install_joined_group` (~995) check only `Entry::Vacant`, NOT `taken_context_ids`.
  After take removes the entry, a create/install/respawn resurrects a provider-side group ->
  two live crypto states -> divergent send_sequence/sender_key. FIX: guard both on taken set.
- **CM-002 Recovery seal option (a) transient-materialize = nonce reuse.** build_restored_owned
  from a fixed snapshot -> seal uses snapshot send_sequence S -> increments only the DISCARDED
  transient -> every subsequent seal from same snapshot reuses (epoch,S). Compromise recovery
  does >=2 seals/snapshot (revoke_ucans seq1 + rotate_key_packages seq2) each rematerializing =
  reuse in the HONEST path. Retries amplify. Stale snapshot seals under a rotated-out
  (compromised) sender key. Option (a) is MOST abusable. Provider recovery_seal (b) is
  fail-closed (recovery-suppression risk, not crypto catastrophe). respawn-then-seal (c) is
  nonce-safe (authoritative persisted send_seq). Planner rec of (a) is DANGEROUS.
- **CM-003 Crash-respawn send_sequence rollback -> nonce reuse.** respawn_from_snapshot
  (supervisor.rs:4568) restores snapshot verbatim, NO epoch bump. Sends between snapshots
  advance send_tracker in-memory only; crash before persist -> reset to snapshot -> reuse.
  Watchdog respawn amplifies: attacker crashes one actor (panic in deliver_incoming) to force
  reuse on victim's next send. Plan only covers ROTATION persist-before-ack, not ordinary send.
  FIX: mandatory epoch bump on respawn OR sync-persist send_seq before emit.

## HIGH
- **CM-004 send_tracker reconcile rollback-after-emit.** handle_send_message
  (actor/handlers/messaging.rs:406) rolls back send_tracker to high_water_before on transport
  Err/timeout. Today crypto-inert (provider send_sequence is authoritative + rollback-immune).
  Once state.seal (state.rs:1754) is authoritative, rollback after a ciphertext may have hit the
  wire (timeout != not-delivered) reuses the nonce. Must make the crypto seq rollback-immune on
  the emit path. Also: remove the Step-1 duplicate reserve+commit or send_seq double-advances.
- **CM-005 D2 cold-restart floor omission.** restore_crypto_state_with_floor_guard
  (lifecycle_helpers.rs:1772) must route build_restored_owned's RestoredFloors into
  validate_and_merge_all_floors on empty-registry cold restart. If omitted, registry floor=0 ->
  replay of old-epoch sender-key messages accepted. Pipeline assertion INSUFFICIENT (gameable by
  `let _ =`); needs behavioral replay-rejection test.
- **CM-006 build_restored_owned never records taken_context_ids** (provider.rs:2652) -> after
  respawn the context is invisible to the one-way guard (widens CM-001; provider seal returns
  "never created" not "owned by actor").
- **CM-007 Wrapping keypair torn read.** wrapping_public_key/wrapping_secret are SEPARATE
  ArcSwaps; build_restored_owned does two separate stores. Any "combined accessor" that does two
  loads cannot be atomic -> (pub_v1, sec_v2) mismatch. Needs single ArcSwap over the pair.

## MEDIUM
- **CM-008 N2 residual key material.** state.rs destroy_mls_group (2472) nulls only the group;
  sender_key + sender_key_store (OTHER members' keys) + member_wrapping_keys linger, old
  sender_key un-zeroized. If atomic core forgets to discard the whole PerContextState at any
  destroy site (TTL terminal, close, broadcast no-op) -> memory-disclosure exfil of keys that
  should be destroyed -> decrypt retained relay blobs. Doc contract exists; enforcement doesn't.
