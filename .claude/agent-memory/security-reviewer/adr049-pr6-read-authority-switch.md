# ADR-049 PR-6 Atomic Read-Authority Switch (b61618887) -- 2026-07-13

Reviewed `feat/adr049-pr6-atomic-read-authority-switch`. Deletes MLS provider floor
mirrors; Supervisor Class-M floor registry (`context/supervisor/floors.rs`) is now the
SOLE authoritative anti-replay/anti-rollback home. VERDICT: SOUND (fail-closed, one-home,
durable). No CRITICAL/HIGH. Two OBSERVATIONS.

## Confirmed sound
- G1 fail-closed: 3 seams in messaging_helpers.rs all use `check_and_advance_*(..)?`:
  recv (2956), remote-epoch gate-before-install (2979 before set_sender_key_unchecked 2986),
  local-rotation mirror_forward (3015). Caller `deliver` (1463) propagates `?`. G1 grep empty.
- No 4th ungated PROD key-install path. set_unchecked sites: 1374/1498 local send-side key
  (own DID), 2556 restore (floor-merged via validate_and_merge), 1742 gated seam. Remote key
  enters store ONLY via decrypt_and_dispatch→gate, or restore→merge.
- D2 durability: restore_crypto_state returns RestoredFloors{sender_epochs,recv_sequence};
  restore_crypto_state_with_floor_guard (lifecycle_helpers.rs:1770) merges blob→registry.
  validate_and_merge guards on `incoming.is_empty()` (floors.rs:449/558) NOT live registry, so
  COLD restart (empty registry, non-empty blob) populates. Export G2: all 6 prod callers use
  deps.supervisor.export_*. Blob recv floors sourced from registry param.
- validate_and_merge two-pass (validate-all-before-apply) under ONE entry() guard → rejected
  merge leaves registry untouched; crypto destroyed on Err (BUG-1 rollback).
- Error taxonomy: From<FloorAdvanceError>→ContextError::CryptoFailed(Display). Display carries
  did+epoch/seq (protocol metadata, not secrets). No downgrade to loggable.
- remove_member_floors (floors.rs:679): member-granular prune both maps under one guard,
  idempotent, fail-safe (over-reject only). D3 whole-membership-sweep divergence documented +
  orchestrator-accepted. Sound.

## Observations (non-blocking)
- OBS-1 (latent footgun / misuse-resistance): store_member_sender_key (provider.rs:1697) —
  PULL-response requester install — was NOT decomposed symmetrically to the push path. It still
  installs via set_unchecked internally, discards the epoch, no registry gate; defers to a
  doc-comment. ZERO production callers today (only scp-testing harness + tests) → no live
  fail-open. But strictly less safe than process_incoming_sender_key twin and gives a future
  caller no epoch to gate with. Plan §1 said "return (SenderKey,u64)... 4th gate site" —
  only partially followed. If pull path ever wired to prod = fail-open. Recommend decompose to
  return (SenderKey,u64) OR gate internally.
- OBS-2 (doc precision): restore guard "registry left UNCHANGED (atomic)" is strict only if the
  FIRST (epoch) merge rejects. If epoch merge succeeds then recv merge fails, sender_epochs
  already advanced (monotone, within ceiling) while crypto destroyed + import rejected. Fail-SAFE
  (floors only rise; idempotent retry) but phrasing overstates. One-line caveat suffices.
- Known accepted LOW residuals (pre-existing, correctly in-code documented): unbounded recv
  SEQUENCE axis (self-healing DoS, floors.rs:509-526); legacy-snapshot one-boot window bounded
  by MAX_EPOCH_ADVANCE (provider.rs:2519-2551).
