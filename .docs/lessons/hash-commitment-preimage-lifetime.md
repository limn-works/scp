# Hash-Then-Reveal Commitments Require Preimage Retention From t=commit Through t=reveal

**Date:** 2026-04-27
**Source:** SCP-1717 — pre-rotation key destroyed at create time, then required at migrate time. Layered on the earlier SCP-214 review (`pre-rotation-key-must-be-stored-at-creation.md`) which predicted this exact failure on 2026-03-01.

## Rule

Any hash-then-reveal commitment scheme — the commitment (hash) is published at time T, the preimage is required at time T+N — must persist a reference to the preimage from T through T+N on every reachable code path. The persistence boundary is set by the longest possible delay between commit and reveal, not the typical case.

If the commitment-publishing code path destroys or fails to retain the preimage before any reveal-time call site, the invariant is broken cryptographically. Verifiers will reject the proof; reveal becomes impossible.

## SCP examples of hash-then-reveal commitments

| Commitment | Preimage | Spec location | Lifetime |
|------------|----------|---------------|----------|
| `pre_rotation_commitment` (32-byte SHA-256) | Pre-rotation key public bytes | §3.7, §9.7.4.1, ADR-003 §4b | Identity creation → next Layer 2 migration (potentially years) |
| KeyPackage commitment | KeyPackage init key | RFC 9420 / §9.7.3 | KeyPackage publish → KeyPackage consumption (single-use) |
| Sender key commitment | Sender key | §9.16.2 | Key distribution → key destruction |
| MLS leaf commitment | Leaf encryption key | RFC 9420 §7 | Epoch advance → next epoch advance |

For each, the preimage must remain in *some* custody until the reveal-time code path is reachable. The custody discipline (HSM, cold storage, in-memory, encrypted backup) varies by threat model, but the basic invariant is the same: don't destroy the preimage before the reveal site.

## Detection pattern

Static review:
1. Grep for hashing primitives over keys: `Sha256::digest`, `compute_commitment`, `*_commitment`, `key_commitment`, `commitment_bytes`.
2. For each match, identify the preimage variable. Where is it generated? Where is it stored (or not)? Where is it required again?
3. If any `destroy_key`, drop, scope-end, or end-of-function precedes any reveal-time site on a reachable code path, the invariant is broken.
4. Test: write an integration test that runs the full commit-to-reveal cycle and asserts the spec invariant on the emitted artifact bytes (see `behavioral-invariant-must-be-asserted-on-every-bridge.md`).

## What went wrong in SCP-1717, and what holds now

`DidDht::create_new_identity_keys` published `SHA-256(pre_rotation_public)` as a commitment, then called `key_custody.destroy_key(&pre_rotation_key)`, following spec §9.7.4.1 #5f literally ("destroy from memory after backup is confirmed"). `InMemoryKeyCustody` carried no backup callback, so that destroy ran unconditionally. At migrate time native bridges generated a fresh keypair, which broke `SHA-256(revealed_key) == commitment` from spec §3.7.

A custody-handoff design resolved it. `scp-platform` exposes `PreRotationCustody` beside `KeyCustody`, and a distinct `PreRotationKeyHandle` carries no `From`/`Into` in either direction, so a type system separates pre-rotation material from operational material. `ScpIdentity` carries `pre_rotation_commitment: [u8; 32]` plus three operational handles (`identity_key`, `active_signing_key`, `agent_signing_key`), and never carries pre-rotation private bytes. `DidDht::create_identity` returns `(ScpIdentity, DidDocument, PreRotationKeyHandle)`; `migrate_identity` takes that handle plus a `&impl PreRotationCustody`, and consumes an old entry to mint a new `#0`.

Two rejected alternatives: amending §9.7.4.1 #3 and #5f to exempt in-memory custody profiles, and retaining `pre_rotation_key: KeyHandle` on `ScpIdentity`, which would hand an attacker who compromises operational custody a recovery backstop as well.

**Live residual:** `InMemoryPreRotationCustody`, a shipped default backend, satisfies type-level isolation but not §9.7.4.1 §3 substrate isolation, so a production deployment substitutes a hardware-backed or callback-based `PreRotationCustody` implementation (see `.docs/lessons/custody-substrate-isolation-holds-at-rest-not-in-transit.md`).

## Companion lesson

`.docs/lessons/pre-rotation-key-must-be-stored-at-creation.md` — narrower, predicts the SCP-1717 fix from SCP-214 review. This lesson is the generalization: every commit-then-reveal scheme has the same structure.
