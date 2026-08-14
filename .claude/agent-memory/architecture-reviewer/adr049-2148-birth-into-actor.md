---
name: adr049-2148-birth-into-actor
description: Architecture review of PR #2186 (#2148) — MlsCryptoProvider per-context-state dissolution / birth-into-actor. APPROVED.
metadata:
  type: project
---

PR #2186 / issue #2148 — ADR-049 §6/§15 closing edge: dissolve the `MlsCryptoProvider`'s per-context state.

**Verdict: APPROVED** (2026-08, HEAD 40809c667). The change executes exactly what ADR-049 §6 last-para + §15 final-paras were pre-reconciled (commit bddab4a00) to describe.

**What it does:** deletes provider `contexts` DashMap + `taken_context_ids` DashSet + `broadcast_keys` DashMap and every method reading them (`take_crypto_state`, `with_context`, `create_mls_group`, `generate_sender_key`, `init_broadcast_key`, `destroy_mls_group`/`_sender_key`, `context_crypto_present`, `install_joined_group(&id,..)` slot form, etc.). Birth constructors (`create_mls_group_with_context`, `install_joined_group`, `build_restored_owned`) now return `OwnedMlsCryptoState` by value; CREATE/WELCOME/restore caller seeds it onto the actor's `PerContextState` via `seed_encrypted_crypto_from_owned` BEFORE spawn. Provider reduced to node-level MLS-birth/HPKE helper (local_did, clock, mls_backend, hpke_backend, ArcSwap wrapping keypair). Pure NAME rename tracked #2185.

**4 invariants — all hold.** (1) Class-S/C: crypto is Class-C (coalesced, per §15/#2149); seed happens at construction pre-ack (not via cell); teardown `dispose_secrets` via `class_c_view()`; terminal Expired/Closed persists fail-closed BEFORE dispose — no Class-S seeded via Class-C. (2) Send: birth ctors sync→owned (Send); recovery seal drops `class_c_view` before transport await. (3) Capability: STRENGTHENED — deleting the shared `contexts` map removes a latent actor→other-context reach through shared `deps.crypto.with_context(other)`. (4) block_in_place: no new sites.

**Double-birth guard = sound 3-layer, not literally "sole."** ADR's "registry insert is sole double-birth guard" is accurate in its narrow framing (it replaces the deleted redundant provider cross-map guard that was the #2167 TOCTOU source). Verified guard stack across CREATE (dispatch_lifecycle_direct)/WELCOME (spawn_actor_from_welcome @13416)/RESTORE/respawn: `bootstrap_spawn_lock` serializes same-id bootstraps → durable Precheck-D/B8 (load_context terminal/first-writer refuse) → registry `write_lock` check-then-insert first-writer-wins (spawn_actor_with_watchdog @4540). #2167 impossible by construction (no cross-map check-then-insert left).

**Findings (no blockers):**
- MEDIUM stale-doc scar tissue: `state.rs` `seed_encrypted_crypto_from_owned` doc (~2181) still cites "take_crypto_state"/"taken_context_ids"/"Mode-A take"; the `#[allow(dead_code)]` reason (~2143) + comment (~2131) cite "retained provider teardown seam e.g. destroy_mls_group" (DELETED); `provider.rs` `OwnedMlsCryptoState.send_sequence` field doc (~312) says "at take-time … provider left off." Fix inline.
- LOW: `OwnedMlsCryptoState` struct has no `#[must_use]` — the "birth-returns-owned, caller-seeds" seed obligation is by-convention only (forget-to-seed → live actor with mls_group=None). Add struct `#[must_use]`. (WELCOME has a durability gate backstop; CREATE has only a debug_assert.)
- LOW: blanket `#[allow(dead_code)]` on whole `impl PerContextState` crypto-twins block — reason now stale post-dissolution; tighten so it can't mask a future unwired twin (dispose_secrets IS wired: ttl.rs:759, ttl_close_helpers.rs:903, lifecycle.rs:612).

**Strengths:** FFI `CloseOrchestrator::new()` drops its crypto arg — removes a latent FAIL-OPEN (old bridge destroyed on a fresh EMPTY per-call provider, reporting success while touching nothing; real teardown is now the actor's CloseContext→dispose_secrets). Enforcement EXPANDED (pipeline_wiring provider_steady_state_crypto_methods_are_deleted + check-deleted-primitives.sh field bans), not weakened. Broadcast key home intact: `init_broadcast_context`→`add_author`→`BroadcastAuthorState::new` mints real `generate_sender_key()` on actor BroadcastState, rides Class-S snapshot.
