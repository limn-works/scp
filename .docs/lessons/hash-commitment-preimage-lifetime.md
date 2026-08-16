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

A custody-handoff design resolved it. `scp-platform` exposes `PreRotationCustody` beside `KeyCustody`, and a distinct `PreRotationKeyHandle` carries no `From`/`Into` in either direction, so a type system separates pre-rotation material from operational material. `ScpIdentity` (`crates/scp-identity/src/lib.rs:80`) carries `pre_rotation_commitment` plus two operational handles, `identity_key` and `active_signing_key`, and an optional `agent_signing_key`; it never carries pre-rotation private bytes. `DidDht::create_with_agent_key` (`crates/scp-identity/src/dht.rs:1091`) takes `&impl KeyCustody` and `&impl PreRotationCustody` separately and returns `(ScpIdentity, DidDocument, PreRotationKeyHandle)`. `DidDht::migrate_identity` (`dht.rs:1448`) takes that handle plus both custody references, and consumes an old entry to mint a new `#0`.

Two rejected alternatives: amending §9.7.4.1 #3 and #5f to exempt in-memory custody profiles, and retaining `pre_rotation_key: KeyHandle` on `ScpIdentity`, which would hand an attacker who compromises operational custody a recovery backstop as well.

**What remains unbuilt.** `InMemoryPreRotationCustody` is this repository's only implementation of `PreRotationCustody`, and it sits under a testing module — `crates/scp-platform/src/testing/pre_rotation_custody.rs:67` holds its sole `impl`, gated to a test harness by ADR-062 §Decision 6. A shipped build therefore reaches no pre-rotation backend at all. Identity creation fails closed with typed code SCP-IDENT-1059 rather than minting that nullifier, which `crates/scp-ffi/common/src/error_codes.rs:284` documents and attributes to CLAUDE.md's builder tenet forbidding a dev stand-in on a production path. No hardware-backed or callback-based implementation exists yet; building one is what closes this gap, and issue #1729 plus RFC #2130 track it.

Read that state as this lesson's own rule turned inward: a preimage nobody can retain is a commitment nobody can reveal, so an honest typed error beats a stand-in that pretends custody happened. Substrate isolation, once a real backend lands, carries its own constraint — see `.docs/lessons/custody-substrate-isolation-holds-at-rest-not-in-transit.md`.

## Companion lesson

`.docs/lessons/pre-rotation-key-must-be-stored-at-creation.md` — narrower, predicts the SCP-1717 fix from SCP-214 review. This lesson is the generalization: every commit-then-reveal scheme has the same structure.
