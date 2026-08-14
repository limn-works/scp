---
name: adr049-pr7-crypto-move
description: ADR-049 PR-7 (SCP-CRYPTOMOVE-001) steady-state crypto MOVE off MlsCryptoProvider onto actor PerContextState/ContextCryptoState — pipeline_wiring faithfulness + scope review at 2a916e9c2
metadata:
  type: project
---

# ADR-049 PR-7 crypto MOVE review @ 2a916e9c2 (branch feat/adr049-pr7-atomic-crypto-move) — 2026-07-15 — ALIGNED

Verdict: ALIGNED, 0 BLOCKER/HIGH/MEDIUM. Only LOW/NIT (stale doc refs). pipeline_wiring repoint is FAITHFUL.

**What PR-7 is:** 11 steady-state crypto methods (seal, open, advance_epoch, rotate_sender_key, remove_member, remove_member_sender_key, mls_encrypt_management, local_sender_key_epoch, export_crypto_state, restore_crypto_state, drain_pending_sender_key_messages) MOVED off `MlsCryptoProvider` (grep `fn <m>(` in crypto/mls/provider.rs = 0 for all 11) onto actor-owned `ContextCryptoState` in context/actor/state.rs. Birth/restore seam methods RETAINED on provider (create_mls_group, add_member, install_joined_group, take_crypto_state, store_member_sender_key, validate_key_package, wrapping_keypair, destroy_*). Note asymmetry: add_member retained, remove_member moved — internally consistent w/ the new test's own doc.

**pipeline_wiring.rs FAITHFUL (the key check):** every repoint preserves the original PROPERTY.
- New `STATE_SRC` const = state.rs. seal/open assertions repointed PROVIDER_SRC→STATE_SRC (create_outer_envelope/encrypt_sender_layer/decrypt_sender_layer/strip_padding). First `fn seal(`/`fn open(` in state.rs (1666/1751) is the ContextCryptoState one — correct target.
- send_message seal: `build_encrypted_envelope`(deleted)→`build_encrypted_envelope_actor` (calls crypto_state.seal). build_encrypted_envelope SPLIT into build_inner_wire (shared: wrap_content/create_inner_envelope_raw/attach_provenance) + build_encrypted_envelope_actor. create_inner_envelope/wrap_content/attach_provenance repointed to build_inner_wire.
- read-authority gate (pr6 test): install marker `set_sender_key_unchecked`→`sender_key_store`+`set_unchecked` (AND); gate-before-install `check_and_advance_sender_epoch`(msg_helpers:3168) < first-code-occurrence `sender_key_store`(install:3175). Parser strips comments (parser_preserves_call_order_through_noncode), so comment at :3159 mentioning sender_key_store doesn't false-trip. Property preserved.
- ADDITIVE (weakens nothing): `provider_steady_state_crypto_methods_are_deleted` (one-way move, no dual-home); `adr049_pr7_sender_key_answer_is_actor_native_and_enqueued_for_transmit` (§9.16.2 ANSWER: cs.handle_sender_key_request + pending_distributions + nonce_dedup.record NOT xctx_nonce_dedup).

**Scope clean — #2049/#2032 NOT smuggled:** all diff hits for 2049/2032/auto-pull/wrapping-key/request_sender_key are in DEFERRED comments/docstrings or TEST harness stand-ins (welcome_delivery.rs, two_party_test_support.rs drive the pull externally — the ADR-sanctioned stand-in per §480-486, ADR-049:483). Production actor loop does NOT initiate pull. Aligns with ADR boundary.

**Completeness sweep verified:** deleted provider sender-key methods now called on actor state at ALL prod sites — leave (lifecycle:415 rotate), remove (lifecycle:1032/1074/1113), revoke (governance:998/1486/1503), reset (governance:2676/2702), execute_add_member (governance:1187, GAP B). NOTE: GAP B (join-time sender-key PUSH in execute_add_member) was INITIALLY MISSED — only join_context path wired — then fixed in commit b32181ea2. Validates spot-checking every call site, not just the obvious one.

**Stub fixed:** open_inner_envelope deferral stub (from 46be0c881) properly replaced (commit 41cfd92a0) by real read-only actor command MessagingCommand::InspectIncomingInner (feature=testing gated, non-mutating except intrinsic MLS ratchet). No remaining todo!/unimplemented!/Err("pending")/#[ignore]. Remaining `panic!()` are test match-arm exhaustiveness (enforcement commit 2a916e9c2 converted top-level test panics→expect).

**Cross-layer send_checkpoint/send_heartbeat = CORRECT classification:** both `pub async fn` in scp-runtime. send_heartbeat called by scp-ffi/common/src/heartbeat_scheduler.rs:98 (internal scheduler via Supervisor::send_heartbeat) — internal helper the FFI layer drives, NOT a user-facing SDK op needing capability-matrix entry. send_checkpoint internal-only. [cross-layer: pub-crate-visibility] marker is honest, not masking a missing FFI export.

**LOW/NIT findings only:**
- messaging_helpers.rs stale/contradictory docs: line 100 says "build_encrypted_envelope is DELETED" but module-doc line 24 still lists `[build_encrypted_envelope]` as helper #1, and lines 111/112/198 call it "the retained provider path". 4 broken intra-doc links `[build_encrypted_envelope]` to deleted symbol. docs.yml runs `cargo doc` WITHOUT -D warnings → warnings only, non-blocking. Fix: update module doc + retitle "retained provider path"→"deleted provider twin".
