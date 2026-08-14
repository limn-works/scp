---
name: 2199-attestation-honesty
description: Black-hat audit of SCP #2199 (KeyDestructionAttestation honesty gating on observed DisposalOutcome)
metadata:
  type: project
---

# #2199 — KeyDestructionAttestation honesty (audit verdict)

Fix: `dispose_secrets() -> DisposalOutcome` (observes `mls_group.is_some()` +
`sender_key.is_some()||!sender_key_store.is_empty()` BEFORE nulling). Orchestrator
`destroy_ephemeral_keys` takes `disposal` param (deleted hardcoded true). ttl.rs
STEP bits gated on observed outcome. finalize_close builds honest attestation
(log-only, #2215 defers recording). Fabricated UniFFI pre-disposal build deleted.

## Could NOT make it forward-lie (destroyed=true, material survives)
- Observe + destroy in ONE sync no-await fn; actor owns state exclusively → no race.
- destroy_group total; store cleared; flag true ⟺ present ⟺ destroyed.
- finalize deletes snapshot; ttl persists Expired (restore-skips non-Active) → no
  crypto rehydration after a {true}. Shutdown disposes in-memory-only (discarded
  outcome, no attestation) → respawn rehydrates but builds no attestation.
- No prod hardcoded `true` remains (all remaining are tests).

## REAL FINDING — MEDIUM liveness regression (STEP-bit completion/provenance conflation)
- `is_complete() == (completed_steps == ALL_STEPS)` needs BOTH destroy bits.
- ttl.rs now sets STEP_MLS_DESTROYED / STEP_SENDER_KEY_DESTROYED ONLY when the
  observed outcome flag is true. An Encrypted Ephemeral/Summary ctx reaching TTL
  with a partially/fully-absent crypto sub-component (group present + sender-key
  absent, or already-disposed) sets a SUBSET → is_complete() NEVER true → actor
  NEVER despawns, retries forever (bounded backoff, no give-up; mod.rs:870/938).
- OLD code deliberately set both bits for the "nothing to tear down / already-
  disposed" case to prevent this exact spin — #2199 removed that guard.
- None-crypto branch is prod-UNREACHABLE (Broadcast=Full → needs_key_destruction
  false → block skipped; Encrypted always Some). Partial-Some reachability unproven.
- NOT a security lie (keys genuinely destroyed) — a resource/liveness DoS.
- Root cause: STEP bits serve TWO masters — completion ("no material remains":
  absent OR destroyed) vs provenance ("destruction observed": destroyed only).
  Fix separates them; don't gate completion on the provenance observation.

## LOW findings
- `pending_distributions` (serialized sender-key distribution msgs, key-bearing)
  is CLEARED by dispose but NOT observed by `sender_keys_present` → inverse-lie
  precision gap only (state w/ empty key+store but non-empty pending → flag false
  while real material destroyed). No forward lie.
- Honest attestation is LOG-ONLY (finalize_close tracing::info!, not persisted/
  returned/evented). ttl STEP bits surface to consumer only via ExpiryFailed
  (FAILURE path; happy path emits unit Expired). KeyDestruction/CloseOrchestrator
  now DEAD-in-prod (test-only callers). So no verifier receives honest destroyed-
  flags on success path yet. "Lie killed" true; replacement honesty not yet observable.
- #82 caveat: mls_group_destroyed=true means signer FREED not ZEROIZED (pre-existing).

## Charge 4/5 clean
- Old bridge attestation was also discarded (log-only match), issued no real relay
  deletion (empty urls/blobs). Real relay-delete duty lives in ttl::finalize_close,
  still wired. No downstream dependency lost.
- No attacker-triggerable panic/unwrap on disposal/finalize path.
