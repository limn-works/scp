---
name: adr049-2148-birth-into-actor-audit
description: Audit verdict for PR #2186 / issue #2148 — MlsCryptoProvider per-context-state dissolution (birth-into-actor); the #2167 TOCTOU "by construction" claim
metadata:
  type: project
---

# PR #2186 / #2148 birth-into-actor — SHIP (verified 2026-08-01)

Deletes provider shared per-context maps (`contexts`/`taken_context_ids`/`broadcast_keys` + ~12 methods).
Birth constructors return `OwnedMlsCryptoState` locally; CREATE/WELCOME/RESTORE seams seed the
actor's `PerContextState` directly before spawn. Net -2336.

**Why:** The #2167 "impossible by construction" claim is TRUE, not marketing. #2167 was a
cross-map check-then-insert race between `contexts` (Entry::Vacant) and `taken_context_ids`.
Both maps deleted → no gap. Double-birth guard now solely: (a) global `bootstrap_spawn_lock`
serializes all four birth paths (Create/Import/Restore/Welcome), (b) atomic registry
check-then-insert under `write_lock` in `spawn_actor_with_watchdog` (supervisor.rs:4540-4547),
first-writer-wins. Loser drops owned crypto locally (zeroizes) — no shared mutable provider
map left to corrupt. Genuine root-cause fix.

**Seams verified sound:** owned crypto seeded onto `state` BEFORE spawn; every early-return
drops `state` (zeroize). WELCOME seam (supervisor.rs ~13760) has prechecks A-D + step-5 atomic
insert backstop. seed_encrypted_crypto_from_owned is production (state.rs:2191).

**Deletion equivalence OK:** provider `destroy_mls_group`/`destroy_sender_key` were NO-OPs for
taken contexts (all prod contexts post-PR-7); real teardown is actor `dispose_secrets`
(state.rs:2107 — OpenMLS destroy_group + ZeroizeOnDrop) at close/finalize/TTL/shutdown seams.
KeyDestructionAttestation `destroyed:true` was ALREADY hardcoded in old code against a
fresh empty per-call provider — observability marker, not a verified proof, PRE-EXISTING.

**Tests real, not theater:** two_party_test_support rewrite drives real reserve→owned-birth→
actor add_member→ConfirmConsume→owned-birth→§9.16.2 pull end-to-end. golden_* suite (16 tests,
state.rs:3959+) does real cross-party seal(Alice)→open(Bob) byte-identical, plus rotate/
advance_epoch/remove_member/export-restore/destroy parity. Slice-1 byte-parity-vs-insert tests
correctly retired (insert path deleted; behavioral golden tests are stronger replacement).

**Enforcement:** check-deleted-primitives.sh gets bounded denylist for the 6 deleted symbols;
runs clean, no self-trip. cargo check -p scp-runtime passes.

**Only soft note (MEDIUM, pre-existing):** KeyDestructionAttestation is not cryptographically
gated on the actor's actual dispose — it's observability. Real disposal separately guaranteed
by actor finalize. Not introduced by this PR.
