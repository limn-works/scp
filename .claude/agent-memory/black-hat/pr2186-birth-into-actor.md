# PR #2186 / #2148 birth-into-actor — provider per-context-state dissolution

Dissolves MlsCryptoProvider maps (contexts/taken_context_ids/broadcast_keys). Births return
OwnedMlsCryptoState locally; caller seeds actor PerContextState. Close destroys via actor dispose_secrets.

## Findings
- **NO active concurrent double-birth.** ALL production birth paths (create 3112, import 3312, restore,
  respawn 4844, welcome 13416, standing 10658) hold the GLOBAL `bootstrap_spawn_lock` (Mutex<()>),
  serializing every bootstrap node-wide. Registry insert in `spawn_actor_with_watchdog`
  (supervisor.rs:4540-4546) is first-writer-wins under write_lock. Loser's `state` (owns crypto)
  consumed by-move → drops on Err. So two births can't both seed.
- **[MEDIUM/HIGH] Mislabeled invariant — welcome persists BEFORE register.** WELCOME order:
  birth→seed→persist(step4)→register(step5). CREATE order: birth→seed→register→persist(finalize_create).
  Welcome relies on bootstrap_spawn_lock for durable correctness, but PR comments repeatedly assert
  "the supervisor registry's atomic first-writer-wins is the SOLE and sufficient double-birth guard."
  FALSE for welcome durable path: without the global lock, a losing welcome would overwrite the winner's
  snapshot with a DIVERGENT group then delete it on its Err arm (delete_context) → winner live with NO
  durable snapshot. Invariant actually lives in bootstrap_spawn_lock+PrecheckA/D, not the registry.
  Fix: reorder welcome to persist-after-register (match create) OR correct comments.
- **[MEDIUM] taken_context_ids removal widens post-close resurrection (challenges ADR "redundant" claim).**
  Explicit Ephemeral/Summary close (ttl_close_helpers finalize_close:911) DELETES durable snapshot, so
  B8 (create, is_terminal on None) and Precheck D (welcome, Some on None) both see None → permit re-birth.
  Comment ttl_close_helpers.rs:914-915 is self-contradictory ("anti-resurrection refuses terminal id AND
  snapshot deleted" — deleting the snapshot removes the terminal id it would refuse against). Mitigated
  because explicit close leaves actor REGISTERED (command dispatch doesn't break run loop; only TTL-timer
  arm despawns), so Precheck A blocks — UNTIL a Shutdown/crash despawns the closed actor. taken_context_ids
  was the in-process backstop for exactly the despawned-closed-no-snapshot window. Local-driven, narrow.
- **[LOW] Decoupled destruction attestation (fail-open latent).** KeyDestructionOrchestrator now ALWAYS
  reports KeysDestroyed (infallible); apply_ttl_terminal_transition (ttl.rs) marks STEP_*_DESTROYED even
  when crypto_state==None. Safe today (Encrypted⟹Some) but attestation no longer performs/verifies the
  zeroization it asserts. Previously coupled (orchestrator held crypto, returned CryptoFailed).
- **[LOW] "drop zeroizes ScpMlsGroup" comments overstate.** destroy_group (scp-mls group.rs:988) and a
  bare drop BOTH only free InMemoryMlsProvider MemoryStorage without zeroizing (OpenMLS lacks Zeroize,
  documented issue #82; EagerDropSigner zeroizes signer only). So loser-birth "drop zeroizes" is imprecise
  (frees, not zeroizes) but NOT a regression (destroy_group same limitation).
- **Q5 no panic wedge.** seed_encrypted_crypto_from_owned/dispose_secrets/install_joined_group infallible,
  no unwrap/expect/index; create_mls_group_with_context uses `?`; joined_group.epoch() map_err'd.
- **Q6 no throttle removed.** Births gated by KeyPackage single-use (welcome) + bootstrap paths; maps had
  no rate-limit.
