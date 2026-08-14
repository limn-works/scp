---
name: adr049-pr7-crypto-move
description: CLEAN review of ADR-049 PR-7 (feat/adr049-pr7-atomic-crypto-move) — seal/open crypto moved from MlsCryptoProvider onto actor-owned ContextCryptoState
metadata:
  type: project
---

# ADR-049 PR-7 (SCP-CRYPTOMOVE-001) — sender-key crypto move onto the actor

Reviewed at tip 2a916e9c2 (Jul 2026). **CLEAN — no BLOCKER/HIGH/MEDIUM production defects.**

**Why:** PR moves steady-state seal/open/rotate/distribute crypto off `MlsCryptoProvider`
(now empty after `take_crypto_state`) onto the actor-owned `ContextCryptoState`
(`crates/scp-runtime/src/context/actor/state.rs`). Deletes the `#[cfg(test)]` provider
`build_encrypted_envelope` seal twin; retains `build_inner_wire` shared core so wire stays
byte-identical (16 golden tests hold).

**How to apply / what I verified sound (don't re-flag):**
- Drain sequencing: `decrypt_and_dispatch` (sync) pushes a KeyRequest answer onto
  `cs.pending_distributions`; `handle_deliver_incoming` re-acquires the Class-C view AFTER
  the deliver view drops and drains via `drain_and_deliver_sender_keys` (mem::take — no
  dup). KeyRequest returns `Ok(None)` early so no later await can cancel between push+drain.
  `pending_distributions` is NOT in the snapshot (`export_crypto_state` omits it) so no
  cross-restart duplicate send. `deliver_incoming` has exactly ONE caller
  (`handle_deliver_incoming`), which always drains.
- Gate-before-install preserved in both the production KeyResponse arm of
  `decrypt_and_dispatch` and the test-only `LandSenderKeyResponse` handler:
  `check_and_advance_sender_epoch` (fail-closed) BEFORE any cell borrow / `set_unchecked`.
  Old `deps.crypto.set_sender_key_unchecked` (silent no-op on taken context) removed.
- `send_checkpoint`/`send_heartbeat` sync→async conversion: `&mut ClassSCell` is Send, so
  the crypto view is held across the fan-out await; broadcast branch returns `Ok(())`
  (delivery-identical no-op to pre-PR provider "no MLS group" swallow). Heartbeat write-gates
  (require_active + MessagesWrite capability) preserved.
- `encrypt_and_send` None-crypto_state only errors in the non-broadcast else branch; broadcast
  takes the pre-built-envelope branch. `send_message` phase2 `&mut view` scoped so rollback
  arms re-borrow cleanly; seq rollback unchanged.
- `mirror_forward_local_sender_epoch` epoch is now caller-supplied; all 3 flipped sites read
  `local_sender_key_epoch()` POST-rotation (read-authority follows write-authority). Correct.
- `execute_add_member` join-time PUSH: `distribute_sender_key` enqueue is Class-S (rest_mut in
  commit_class_s_keep); drain runs AFTER commit broadcast (transport async). Best-effort on
  failure (member recovers via SenderKeyRequest). Correct ordering.
- `InspectIncomingInner` (test-only): `cs.open` is pure decrypt — no recv-floor advance, no
  nonce_dedup, no Class-M write; only intrinsic MLS ratchet advance → `ok_mutated`. `open`
  does NOT merge commits (returns Control without merge). Correct.
- `build_encrypted_envelope_actor` pub(crate): all callers in-crate (encrypt_and_send +
  `#[cfg(test)] mod tests` in provider.rs:4491/4537 + agent_binding_pipeline_tests). No broken caller.
- New fullstack tests (welcome_delivery.rs) assert exact-plaintext equality through the real
  actor receive path — non-vacuous, exercise the install-onto-actor fix. Realigned
  spawn_from_welcome units assert member_count==Some(2)/lookup/epoch==Some(1) (discriminate
  vs None/0) — weaker but non-tautological; round-trip moved to fullstack.
- `cargo check -p scp-runtime --features testing --tests` passes.

**Pre-existing (NOT this PR, don't attribute):** sender-key PUSH/PULL distributions are
addressed to `context_routing_id` (broadcast); non-target members hit the KeyResponse arm and
fail `process_incoming_sender_key` (sealed to another key). Same for the deleted provider path.
PULL initiation deferred #2049, so no PULL answers broadcast in production. Routing predates PR-7.
