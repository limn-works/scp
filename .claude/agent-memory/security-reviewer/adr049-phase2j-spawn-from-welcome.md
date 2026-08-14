# ADR-049 Phase 2J — spawn_actor_from_welcome (2026-07-02, branch worktree-agent-ac30e75f...)

Reviewed 5 `2j` commits (tip cf080adeb). Adds `Supervisor::spawn_actor_from_welcome`:
Welcome-joined node picks up MLS group+keys → live send-capable actor. Persist-before-ack fail-closed.

## Verdict: SOUND, one MEDIUM hardening finding.

- Join authz CRYPTO-SOUND: join runs through KP-store `ConfirmConsume` →
  `MlsBackend::join_from_welcome` which needs the reserved KP's private init key (in
  `signer_state`) + a Welcome HPKE-encrypted to it; replay blocked by durable
  consumed-init-key set (`MlsError::KeyPackageReplay`). Forged/replayed Welcome cannot join.
- Reservation binding SOUND: `reservation_id` resolves within `owning_did`'s KP store
  (`key_package_store_for(owning_did)`); Welcome must be encrypted to THAT KP or join fails;
  owning_did selects the store → binds owning_did to the reservation. Can't cross-wire.
- First-writer-wins RACE-SAFE: `install_joined_group` uses DashMap `Entry::Vacant` guard
  (atomic), the SAME `contexts` map+gate `create_mls_group` uses, and it is the FIRST gate
  (before actor registry write_lock at spawn_actor_with_watchdog:3996-4005). Loser fails at
  install via `?` (NO rollback of winner). Step 4/5 rollback removes ONLY this call's own
  group (to reach step 5 you must own the crypto slot → nobody else's group can be there).
- Fail-closed CORRECT: persist-before-ack; on step 3/4/5 failure `remove_installed_group`
  (zeroizes MLS key material). Test `persist_failure_leaves_no_half_keyed_actor` non-vacuous
  (asserts group torn out AND no actor registered; mutation arg documented).

## MEDIUM (latent, not yet exploitable — FFI export unwired):
`Supervisor::spawn_actor_from_welcome` is `pub` + takes bare `DID owning_did` (supervisor.rs:10345),
while siblings `build_actor_deps`(2306)/`spawn_actor_with_state`(3910) are `pub(in crate::context)`.
Intended prod seam = OwnedIdentityDid-gated `SupervisorHandle::spawn_actor_from_welcome`
(#[allow(dead_code)], pub(in crate::context) — inert). BUT scp-ffi holds `Arc<Supervisor>` directly
(runtime.rs:168,663,1201). Bare-DID method selects KP store for owning_did, which reconciles that
identity's DURABLE reservations incl private signer_state (key_package_actor.rs:110,358). So raw
method = exact "spawn under an identity you don't own" primitive the OwnedIdentityDid capability
exists to prevent. FIX: make it `pub(in crate::context)` so only the capability-gated handle is
reachable. Recurring pattern: capability-gate siblings restricted, new method over-public.

## Observations (non-blocking):
- context_id caller-asserted, NOT bound to MLS group_id (random per RFC 9420 §12.4.2.1). Matches
  create-path trust model; context_id = local routing label, MLS membership = security boundary.
  Mismatch = self-harm only (no cross-node hijack/inject). Same as create.
- Step-5-failure leftover snapshot (persist ok, spawn fails→crypto rolled back but snapshot stays)
  → restart resurrects. But step 5 can't fail while owning crypto slot → dead branch.
- Join path inlines `ContextRouting::for_mode(false, pseudo.unwrap_or([0u8;32]))` instead of shared
  `build_routing` helper (lifecycle_helpers.rs:133) — cosmetic drift risk.
