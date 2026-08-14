# ADR-049 Phase 2J spawn-from-Welcome (branch feat/adr049-2j-spawn-from-welcome)

Entry point: `Supervisor::spawn_actor_from_welcome` supervisor.rs (~10359).
Round-1 fixes: precheck-A `lookup` up-front (10391), hoisted param validation,
crypto-durability re-check (10510), reject None pseudonym.

## RESIDUALS FOUND (round 2, post-fix)

### BLACK-2J-05 [HIGH] missing bootstrap_spawn_lock
- spawn_actor_from_welcome does install→persist→spawn but takes NO
  bootstrap_spawn_lock; create/import/standing/respawn all take it
  (supervisor.rs 2450/2581/2653/4085; hazard documented 4077-4080).
- Watchdog respawn_from_snapshot runs off-mailbox, only excludes lock-holders.
- Precheck-A `lookup` (checks self.actors only) MISSES during respawn's despawn
  window. restore_crypto_state does BLIND self.contexts.insert (provider.rs:2210,
  no Vacant guard, unlike install_joined_group) → crypto/actor divergence.
- Step-5 duplicate-rollback runs delete_context(context_id)+destroy_mls_group on
  ATTACKER-chosen id → destroys victim's freshly-restored snapshot + crypto.

### BLACK-2J-06 [HIGH] lookup != durable truth (BLACK-2J-01 not really closed)
- lookup (supervisor.rs:3581) reads self.actors only. persist_context
  (providers/persistence.rs:91) is blind overwrite by context_id string, no
  first-writer-wins. ConfirmConsume (key_package_actor.rs:998) does NOT bind
  context_id to the Welcome group — attacker fully controls target context_id.
- Any persisted-but-unspawned context is clobberable: post-restart window before
  restore_all_contexts; non-Active snapshots (skipped, lifecycle_helpers.rs:2836);
  FAILED-restore contexts (skipped 2845, permanent). Attacker overwrites victim
  snapshot with attacker-fabricated one (attacker owns creator_did/params/members);
  resurrects on next restore. Fix protects LIVE contexts only.
- Robust fixes: hold bootstrap_spawn_lock whole body; check persistence for
  existing snapshot before persist (or first-writer-wins persist); derive
  context_id from joined group not caller.

### BLACK-2J-03 residual [LOW]
- 4b durability re-check is a 2nd independent export_crypto_state read; bypass
  needs empty-at-persist then nonempty-at-recheck (transient only, deterministic
  backends safe). Persist should echo bytes written.

## HELD
- Griefing (2J-02): post-consume failures burn only JOINER's OWN KP (reservation
  is caller's own store). No cross-victim burn. OK.
- Single-use: ConfirmConsume consumes reservation durably, one→one join.
- delete_context aliasing: always scoped to attacker's context_id; SHA-256 digest
  keying no feasible collision; damage realized only via 05/06 race.
