---
name: adr049-pr7-crypto-move-15
description: ADR-049 §15 + §9 amendment + PR-7 PRD (crypto-state move) review — contract accurate, two real coherence gaps (restore/respawn mechanism; birth-in-dispatch vs at-spawn)
metadata:
  type: project
---

Reviewed the uncommitted docs PR `docs/adr049-pr7-crypto-move-decision` (ADR-049 §15 new decision + §9 read-authority-switch PR-7 clause + `.docs/prds/adr049-crypto-state-move.json`) off origin/main 8e2110f93 (PR-6 merged).

**Why:** §15 + the PRD become durable provenance for the security-critical crypto-by-move (all per-context `deps.crypto.*` off `MlsCryptoProvider` onto actor `&mut PerContextState`, `take_crypto_state` at spawn). One atomic PR (take is one-way per context — DashMap::remove + taken_context_ids; post-take reads fail-closed `CryptoFailed("context state owned by actor")`).

**How to apply:** Verified accurate — OwnedMlsCryptoState 8 fields exact (provider.rs:317); floors excluded (recv_sequence_tracker dormant HashMap, state.rs:479); send_sequence→send_tracker via from_persisted (sequence.rs:120); domain count 32 helpers exact (lifecycle 16/msg 5/gov 4/ttl 3/trust 3/bcast 1). Invariants (Send, lock-free, cap-reduction, Class-S/M, PR-6 registry-authoritative) preserved.

**Two coherence gaps to fix before landing (NOT blockers to the decision, but the ADR/PRD must resolve them so implementer doesn't ship broken code):**
1. **Restore/respawn crypto-material mechanism unspecified + naive path is broken.** Current `restore_crypto_state_with_floor_guard` (lifecycle_helpers.rs:1770) calls `deps.crypto.restore_crypto_state` which REPOPULATES provider.contexts. On WARM respawn the context is already in `taken_context_ids`, so reusing take_crypto_state fails-closed. §15 respawn para asserts "directly into the new actor, no round-trip through provider.contexts" but §15 birth para says "birth/restore seam, mint-or-install-then-move" — contradictory for restore. Restore must deserialize snapshot → actor ContextCryptoState WITHOUT provider.contexts and WITHOUT take. Neither artifact specifies how restore_crypto_state changes to deliver crypto material to the actor. PRD AC#11 tests the end-state but not the mechanism.
2. **Birth is post-spawn/in-dispatch, not "at spawn / before accepting commands."** state.rs:375 doc: MLS group built INSIDE Create/Join handler in the dispatch loop; mls_group=None between spawn and handler. PRD AC#4 ("reaches take_crypto_state ... before the actor accepts commands" + "just-spawned actor's mls_group.is_some() after create") is false for create/join — take runs in-handler, is_some() holds after the command, not at spawn. AC#4 must split birth (create/join, in-handler take) from restore/respawn (snapshot-seeded, pre-dispatch, no take). Entrypoint list also may omit the fresh-Create command handler seam.

Minor: ~32 omits 4 actor/handlers sites (real total ~36, "~"/"six domains" hedges it); 2 of messaging's 5 are local_did (node constant, exempt, PRD AC#1/#3 handle it); "field-for-field" imprecise (actor mls_group/sender_key are Option→Some wrap); AC#9(b) persist-failure injection assumes a rotation test seam exists (export has force_export_failure; rotation may need one added). §6 boundary (provider = birth/restore seam only in PR-7, create_mls_group/add_member deletion deferred to §6) is a clean staged intermediate EXCEPT for gap #1.
