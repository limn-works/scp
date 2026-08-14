# #2148 birth-into-actor / MlsCryptoProvider per-context-state dissolution (PR #2186) -- 2026-08-01

Reviewed HEAD 40809c667 vs origin/main 037914475. VERDICT: no BLOCKER/HIGH/MEDIUM security regressions; observations only.

## What changed
Deleted MlsCryptoProvider per-context maps (`contexts`/`taken_context_ids`/`broadcast_keys` DashMaps + private ContextCryptoState + destroy_/take_/with_context/create_group_into_slot methods). Births now return `OwnedMlsCryptoState` LOCALLY (create_mls_group_with_context, install_joined_group) and caller seeds actor PerContextState via `seed_encrypted_crypto_from_owned` BEFORE spawn. #2167 cross-map TOCTOU gone by construction.

## Verified sound
- **Double-birth guard** = spawn_actor_with_watchdog (supervisor.rs ~4540): `write_lock.lock().await` then `contains_key`(sync)+`insert`(sync), NO await between = atomic first-writer-wins. Loser returns Err BEFORE tokio::spawn (4557); `state` (owning crypto) drops+zeroizes. CREATE/WELCOME/import/restore all funnel here. Also serialized node-wide by single global `bootstrap_spawn_lock`.
- **WELCOME persist-before-ack**: step 2 birth owned -> 2b seed -> transition -> 3b durability check -> step4 `persist_state_fail_closed` (BEFORE spawn) -> step5 spawn+register. Fail-closed. Precheck A (live actors) + Precheck D (`load_context` durable first-writer-wins) run under bootstrap_spawn_lock BEFORE irreversible ConfirmConsume -> a WELCOME for an already-created id is refused before any consume/persist (no cross-delete of victim snapshot).
- **CREATE**: seed before spawn (lifecycle_helpers ~1785), persist via finalize_create AFTER spawn/register, return Ok after persist. Ordering UNCHANGED by #2148 (diff didn't touch 1787-1804). Asymmetry (CREATE persists post-spawn, WELCOME pre-spawn) is PRE-EXISTING.
- **Removed rollback destroys are SAFE**: each ScpMlsGroup owns its OWN `InMemoryMlsProvider` by value (crates/scp-mls/src/group.rs:196). scp_mls::group::destroy_group (988) is itself Drop-based (drops group/signer, replaces provider) == dropping the whole ScpMlsGroup. So rollback drop of `state`/`owned` == old destroy_mls_group. SenderKey is ZeroizeOnDrop. No zeroization regression.
- **Close/TTL key destruction moved to actor** (ttl.rs/ttl_close_helpers.rs): apply_ttl_terminal_transition + finalize_close now dispose actor-owned crypto via `cell.class_c_view().mode_mut().crypto_mut()` -> Some for live Encrypted, None only for Broadcast(Full, no destruction needed). dispose_secrets infallible+idempotent. Attestation honest.
- **uniffi bridge**: old fresh-per-call MlsCryptoProvider passed to CloseOrchestrator had EMPTY per-context state -> destroy_mls_group was ALWAYS a phantom no-op. Removing it + relying on dispatched CloseContext actor dispose is a CORRECTNESS IMPROVEMENT.
- seed_encrypted_crypto_from_owned consumes all 8 owned fields (send_sequence->send_tracker via from_persisted); no dropped secret.
- check-deleted-primitives.sh additions are ADDITIVE bans (legit coverage). bootstrap_spawn_lock + LIFECYCLE_TIMEOUT preserved. No new capability leak; births use provider node-level local_did (unchanged), per-identity gating still &OwnedIdentityDid.

## Observations (non-blocking, mostly pre-existing)
- dispose_secrets docstring + ttl.rs comment claim bare drop "leaves epoch secrets resident in OpenMLS storage" -- imprecise for the in-memory-per-group model (group owns InMemoryMlsProvider, freed on drop). destroy_group is not meaningfully stronger than drop; its real value is at the LIVE-actor close seam where state is not dropped.
- OpenMLS MemoryStorage is freed but NOT zeroized on teardown (both old+new). Pre-existing, out of scope.
- discard_joined_context teardown is now async-deferred (actor winds down after handle removed) vs old synchronous provider destroy. Keys linger briefly in the winding-down actor; still zeroized. Acceptable.
