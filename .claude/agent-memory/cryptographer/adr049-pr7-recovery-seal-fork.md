---
name: adr049-pr7-recovery-seal-fork
description: ADR-049 PR-7 recovery_send_notification_direct seal fork — nonce analysis, reachability, and option recommendation (deep research 2026-07)
metadata:
  type: project
---

# ADR-049 PR-7 recovery seal fork (supervisor.rs recovery_send_notification_direct)

Deep-research resolution of the SEAL FORK. Base origin/main c34387059 (Preps A-D). Read via `git show origin/main:`.

## DECISIVE crypto fact (Q3)
- Sender-layer AES-256-GCM nonce is RANDOM per-seal via `OsRng.fill_bytes` (scp-protocol/src/crypto/sender_keys/encrypt.rs:59-61). (epoch, send_sequence) go into the AAD ONLY (`build_sender_aad` ~L126), NEVER the nonce.
- => The plan's framing "reused send_sequence -> AES-GCM NONCE REUSE" is a MISCHARACTERIZATION. Reusing send_sequence does NOT collide the sender-layer GCM nonce (random 96-bit, birthday 2^48 like any two msgs). It only (a) makes the AAD identical and (b) trips the receiver replay/dedup floor -> 2nd msg REJECTED (availability, not confidentiality).
- The REAL reuse under option (a) is the MLS layer: `scp_mls::encrypt::encrypt` -> openmls `create_message` (AES-128-GCM, RFC9420 secret-tree). Nonce = ratchet(generation) XOR random 4-byte reuse_guard. build_restored_owned rehydrates the MLS group from `snapshot.mls_storage_entries` (includes generation) — two seals from the SAME snapshot both encrypt at generation G under the same ratchet key, nonce differing only by the 32-bit reuse_guard => genuine (probabilistically-mitigated) AES-128-GCM near-nonce reuse. Realistic trigger: transient recovery seal at gen G (discarded), then node restart -> restore_all_contexts loads SAME snapshot into a real actor which seals at gen G again.

## Reachability (Q1)
- recovery_send_notification_direct reached ONLY when `self.lookup(ctx_id)` misses (dispatch_trust_recovery_command supervisor.rs:3632 — plain mailbox lookup, NO lazy get-or-create spawn).
- PSK "identity-private-state": non-64-hex -> context_id_to_bytes hashes (SHA-256). `seed_identity_private_state_group` is #[cfg(test)]-only (recovery.rs:2110, inside test mod at 1255). PRODUCTION has NO MLS group -> provider.seal already errors "no MLS group" TODAY -> rotate_psk returns false = production no-op. No-op under ALL options post-PR-7 (build_restored_owned errors on empty snapshot; provider recovery_seal errors no-group). NOT decisive.
- Real member (revoke_ucans seq1 / rotate_key_packages seq2 / mls_update seq0, recovery.rs:965/1018/890): reach direct path only when NO live actor. restore_on_startup (supervisor.rs:9110 doc) EAGERLY spawns actors for EVERY persisted Active context so "every participant a recovery arm must drive is RESIDENT" -> in steady state recovery goes MAILBOX -> actor state.seal, NOT direct. Direct real-member path is defensive-only: essentially just the transient crash-respawn gap.
- despawn_actor (supervisor.rs:4971) removes only the actor handle. No idle-eviction despawn found.

## TODAY vs POST-PR-7 (corrects orchestrator lean)
- TODAY (origin/main pre-flip): crypto authoritative in provider.contexts. BOTH recovery paths call provider seal — direct (supervisor.rs:4007) AND actor-mailbox handler (trust_recovery_helpers.rs:388 `deps.crypto.seal`, flipped to state.seal only by PR-7). Contexts NOT taken in steady state. So provider.seal SUCCEEDS today for any provider-resident ctx INCLUDING despawned (despawn doesn't take crypto).
- POST-PR-7: crypto MOVED to actor; taken ctx removed from provider.contexts + recorded in taken_context_ids; with_context (provider.rs:767) fails "context state owned by actor". So provider.seal FAILS for any taken (=used) real ctx.
- => Option (b) is NOT "behavior-preserving with a pre-existing despawned limitation." There is NO despawned limitation today (provider.seal works). PR-7 CREATES it. Option (b) is a mild NEW fail-CLOSED regression for the non-resident real-member direct-path seal — but that path is defensive-only (restore_on_startup residency) and fail-closed/retryable, never a confidentiality break.

## Recommendation
- REJECT option (a) transient-materialize: real MLS-generation reuse footgun (recovery-then-restart, or 2 concurrent recovery seals = TOCTOU). Safe only if it re-implements load->seal->persist-back under a per-context lock — duplicating exactly the actor ownership discipline PR-7 consolidates. Also mutates node wrapping-keypair ArcSwap as side effect (OBS-2). Negative value.
- ADOPT option (b): minimal provider recovery_seal routed through with_context (fail-closed on taken_context_ids). No nonce risk (never materializes a snapshot; only seals still-owned provider-resident ctx). For taken/non-resident real ctx it fails CLOSED with retryable ContextError. Preconditions: (i) MUST route via with_context, never build_restored_owned; (ii) AAD/wire byte-identical to state.seal (both use encrypt_sender_layer + same AAD builder — OK; no ctx sealed by both paths so no send_sequence divergence); (iii) amend §15 zero-grep AC to name recovery_seal (artifact-flow: story first).
- If completeness for the non-resident real-member case is REQUIRED, use option (c) respawn-then-mailbox-seal (seals through authoritative persisting actor, NO reuse) — never (a).
