---
name: adr049-pr7-atomic-core-seam
description: ADR-049 PR-7 (crypto-ownership move) seam-inventory facts — the builder.rs birth-rollback gap and other verified crypto call-site details
metadata:
  type: project
---

ADR-049 PR-7 (SCP-CRYPTOMOVE-001) is the security-critical one-way crypto-ownership move: every steady-state per-context `deps.crypto.*` read relocates onto actor-owned `&mut PerContextState`; provider becomes birth/restore seam only. ADR §15 mandates ONE atomic PR (take_crypto_state is atomic+one-way per context — splitting ships a broken build).

**Why:** reviewing the atomic-core execution plan before it runs.
**How to apply:** when reviewing PR-7 or any crypto-seam story, use these verified call-site facts.

### The builder.rs birth-rollback gap (the key finding)
`context/builder.rs::CreationReceipt::rollback` (origin/main c34387059, ~lines 753/756) calls `crypto.destroy_sender_key` + `crypto.destroy_mls_group` on the PROVIDER. This runs in the CREATION-FAILURE window (before actor spawn/take), so the state is still in `provider.contexts` and provider-destroy is CORRECT — it is birth-seam machinery, analogous to retained `create_mls_group`/`add_member`. Any plan that DELETES provider `destroy_mls_group`/`destroy_sender_key` from the deletion set breaks this path (won't compile; can't re-plumb to actor state because no actor exists on creation failure). PR-7 MUST retain provider destroy_* for the creation-rollback birth seam.

### Verified NON-gaps (don't re-flag)
- `messaging_helpers.rs:3015` `crypto.rotate_sender_key` is a DOC COMMENT, not a call. Messaging has exactly 5 real crypto sites (seal@204, export@2470, local_did@2973, local_sender_key_epoch@3035, local_did@3036) — matches ADR §15's "messaging (5)".
- `supervisor.rs` `crypto.generate_sender_key` occurrences are all in `#[cfg(test)]` (lines 19338+).
- `actor/handlers/trust_recovery.rs:238` and `context/state.rs:215` crypto refs are doc comments only.
- validate_key_package (provider.rs:1130) reads ONLY self.clock → correctly stateless (Prep-C).

### Restore-split facts (build_restored_owned, provider.rs:2652)
Returns `(OwnedMlsCryptoState, RestoredFloors)`, NO contexts.insert. OBS-1 real: it RETURNS floors but does not sink them — caller must route into `validate_and_merge_all_floors` (the current `restore_crypto_state_with_floor_guard` already does this D2 sink at lifecycle_helpers.rs ~1828). OBS-2 real: it mutates node-level wrapping-keypair ArcSwap as a SIDE EFFECT (provider.rs:2824-2835), even on paths that later fail the floor merge — on reject the keypair is left rotated (pre-existing, restore_crypto_state does same).

### N2 zeroization
Inherent `state.rs::destroy_mls_group` (2472) nulls only `mls_group`; sibling sender_key/store/wrapping stay resident. Terminal destroy sites (ttl close) must discard/zeroize the WHOLE PerContextState.

### Seal fork (recovery_send_notification_direct, supervisor.rs:4007)
No `recovery_seal` exists today; provider.seal(1976) goes through with_context (requires context in provider.contexts). Architecture ranking: (c) respawn-then-seal purest but heaviest; (b) retained provider recovery_seal is behavior-preserving + no nonce risk but a §15 DEVIATION (seal is steady-state orchestration §15 moves to inherent, NOT birth-seam state-construction) — needs ADR/story amendment FIRST per artifact-flow + narrowing to fail-closed on taken contexts; (a) transient-materialize has AES-GCM nonce-reuse hazard unless persist-back.

### MlsCryptoSnapshot pub(crate)
Confirmed pub(crate) at provider.rs:111. Correct — actor→crypto edge (actor's export_crypto_state reads the DTO) does not invert layering. Minor smell: shared serialization DTO lives in provider.rs; could hoist to neutral crypto module.
