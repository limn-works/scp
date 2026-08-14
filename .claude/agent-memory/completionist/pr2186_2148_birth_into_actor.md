---
name: pr2186-2148-birth-into-actor
description: Round-2 re-review of PR #2186 (#2148 birth-into-actor) — round-1 findings resolved; new F6 dispose_secrets inconsistency found
metadata:
  type: project
---

# PR #2186 / #2148 birth-into-actor — completionist round-2

Dissolves `MlsCryptoProvider` per-context state; birth constructors return
`OwnedMlsCryptoState` seeded directly onto the actor's `PerContextState` (closes
#2167 cross-map TOCTOU by construction).

**Round-1 findings — all RESOLVED round-2:**
- HIGH (orphaned seam + lost §15(c) test): provider `force_rotation_failure`
  field/init/`arm_rotation_failure_once` DELETED; seam re-homed onto actor
  (`ContextCryptoState.force_rotation_failure` gated `cfg(test,testing)`,
  early-return in `PerContextState::rotate_sender_key` BEFORE mutation). Real
  test `arm_rotation_failure_once_forces_fail_closed_then_normal` in
  state.rs `crypto_ops_golden` asserts epoch-unchanged-on-armed-fail then +1 on
  clear. Genuine, not theater.
- MEDIUM (ADR stale prose): ADR-049 §6 reframed honestly per BLACK-002
  (taken_context_ids deletion = "honest bounded reduction", not zero-cost);
  §9 + §15 carry `[Superseded by #2148]` blanket + inline annotations.
- LOW (with_context denylist): 6 redundant `check-deleted-primitives.sh` rules
  (incl. landmine `\.with_context\(` vs anyhow) DELETED. Retained authority =
  typed `pipeline_wiring.rs::provider_steady_state_crypto_methods_are_deleted`
  (`fn NAME(` + `name: Type` over PROVIDER_SRC) — covers all 6 symbols +
  compiler. Nothing weakened.

**NEW finding — F6 `dispose_secrets` applied INCONSISTENTLY (verdict INCOMPLETE).**
F6 best-effort-zeroizes the OpenMLS Ed25519 signer (SignatureKeyPair has no
Zeroize; scp-mls issue #82 — bare drop frees group storage but leaves signer
resident) on creation-rollback. Wired at builder steps 4/6 and supervisor
welcome steps 4/5, but NOT at:
- builder.rs `create_context` step 7 (append ContextCreated fail) + step 8
  (append MemberJoined leaf fail) — `owned_crypto` drops bare.
- supervisor.rs welcome step 3 (`build_welcome_joiner_state?`, pre-seed), step
  3a (`transition_to(Active)?`), step 3b (durability-check `return Err`) —
  seeded `state` drops bare.
Comments on those branches claim "zeroizing the group/sender key", contradicting
F6's own premise (established elsewhere in the same diff). Best-effort hygiene,
not a correctness hole — but partial application + contradictory comments = a
completeness defect. Fix = call `dispose_secrets()` on ALL post-birth
creation-rollback branches, correct the comments.

Lesson: when a fix closes a "bare-drop-leaves-secret-resident" leak on rollback,
enumerate EVERY early-return between birth and go-live — not just the persist/
spawn ones. Subset application is the "4-of-10" failure mode.
