---
name: adr049-2j-spawn-from-welcome
description: Crypto/crash-safety review of ADR-049 Phase 2J spawn_actor_from_welcome (key-injection fail-closed ordering) — SOUND with 2 LOW defense-in-depth notes
metadata:
  type: project
---

# ADR-049 Phase 2J — spawn-from-Welcome key-injection crash-safety (reviewed 2026-07-02, tip cf080adeb)

Verdict: SOUND. Fail-closed persist-before-ack ordering is correct; no half-keyed-actor window.

## Ordering (supervisor.rs ~10345 spawn_actor_from_welcome)
1. ConfirmConsume(welcome) via KeyPackageStoreActor → durably consumes single-use KP (delete KP record FIRST, then reservation tombstone, B1 order) AND returns the joined ScpMlsGroup by MOVE. Reply type changed () → Result<ScpMlsGroup,_> — type-enforces no groupless-Ok.
2. deps.crypto.install_joined_group(&ctx_bytes, group)? — Vacant-guarded (refuses overwrite → CreationFailed). `?` = NO rollback (correct: must not destroy a pre-existing live group).
3. build_welcome_joiner_state → on Err: remove_installed_group + Err.
4. persist_state_fail_closed → build_snapshot_for_persist reads deps.crypto.export_crypto_state(context_id_to_bytes) → captures the just-installed group into snapshot.mls_crypto_state. On Err: remove_installed_group + Err.
5. spawn_actor_with_state → registers send handle under write_lock (dup-check BEFORE task spawn, no leaked task). On Err: remove_installed_group + Err.

Actor is reachable ONLY after step 5. Snapshot durable after step 4. So crash between install and persist → nothing durable → clean loss (KP burned, re-key). Crash after persist before spawn → fully-keyed snapshot resurrects. No reachable-but-unkeyed window.

## Key facts
- KEY CONSISTENCY (critical): install uses `context_id_to_bytes` (ADR-056 decode of 64-hex), and WORKTREE build_snapshot_for_persist ALSO uses context_id_to_bytes (messaging_helpers.rs:2396). MAIN repo copy was stale (used scp_protocol::context::context_id_bytes = re-hash) — DO NOT trust main-repo reads for this worktree. For a 64-hex id decode≠rehash (state.rs test real_64hex_id_decodes_to_digest_not_sha256 asserts_ne). Consistent in worktree → export finds the group.
- Class M (crash-surviving, max-merge Invariant 2 §23.17.2): picked-up MLS group + locally-minted sender key live in supervisor-owned crypto Arc, captured via export_crypto_state. Correct per ADR-049 lines 184/208.
- welcome_scratchpad: None on fresh joiner — transient, not persisted; consumed by fused join. Correct.
- Sender key minted locally via generate_sender_key() = OsRng CSPRNG; SenderKey is ZeroizeOnDrop → remove_installed_group (destroy_group + drop of ContextCryptoState) zeroizes. access_key_store empty (joiner key delivered out-of-band §9.17.2). sender_key_epoch=1 (per-sender, correct).
- Single-use two-anchor: replay same reservation → ConfirmConsume InvalidState (reservation gone); replay diff-reservation-same-initkey → KeyPackageReplay marker. Own-prior-completion retry now returns Err(InvalidState) groupless (was Ok) — fail-closed. Test second_spawn_reusing_a_consumed_reservation_is_rejected + persist_failure_leaves_no_half_keyed_actor are NON-VACUOUS (mutation arg documented).

## Two LOW / defense-in-depth residuals (non-blocking)
- L1: rollback asymmetry — step-4 persists snapshot durably; step-5 spawn-failure rollback only calls remove_installed_group (in-memory), does NOT delete the persisted snapshot → orphan fully-keyed snapshot could resurrect on cold restart_all_contexts despite caller getting Err. Near-unreachable (step-5 fail = dup registration, pre-empted by step-2 Vacant guard for encrypted ctx). Fix: add best-effort deps.persistence.delete_context(&context_id) on the step-5 rollback. persistence has delete_context.
- L2: export_crypto_state Err at step 4 does NOT fail spawn — build_snapshot_for_persist swallows it (needs_reconnect=true, empty crypto), persist then SUCCEEDS crypto-less, actor spawns → cold-restart resurrects a joiner in needs_reconnect with NO way to reconnect-derive an MLS group (joiners need a fresh Welcome, unlike existing members). Not practically reachable (group just installed → export/serialize succeeds). Fix: treat empty/needs_reconnect crypto export as hard fail in the joiner path.
