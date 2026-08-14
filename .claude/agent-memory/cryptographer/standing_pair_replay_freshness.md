---
name: standing-pair-replay-freshness
description: §5.15.8 standing-pair collision-destroy replay-freshness binding via MLS init-key single-use; cryptographic soundness analysis
metadata:
  type: project
---

§5.15.8 (spec/standing-pair-not-a-saga-v2 @62d6399c3) standing-pair = single-context async creation (NOT a saga; saga framing cut in PR #1793 reversal 2026-06-18).

**Replay-freshness binding (SOUND).** Collision-destroy (`did_hi` tears down its own self-created group on receiving `did_lo`'s canonical Welcome) is gated on a LIVE join: destroy MUST fire only when the Welcome's KeyPackage init key is still unconsumed at the fused-join two-anchor enforcement point (ADR-049 §9). Why sound:
- RFC 9420 §10: a Welcome is HPKE-sealed to exactly ONE KeyPackage's init key. `StagedWelcome::new_from_welcome` (group.rs:691) requires the provider hold that init *private* key. A captured-and-replayed `did_lo` Welcome decrypts only with the same init key.
- `production_backend.rs::join_from_welcome` (489-585): under `join_gate` mutex, consults durable consumed-init-key store FIRST (key = `scp-kp-consumed-initkey/{hex(SHA256(init_key))}`), returns `KeyPackageReplay` if present, runs the join, then durably writes the marker BEFORE Ok. Fails CLOSED if store unattached.
- Therefore: a replayed Welcome whose init key was consumed by the earlier (real) join fails the join → destroy is downstream of a successful join → never fires. Closes captured-and-replayed-`did_lo`-Welcome stale-destroy vector. Init-key single-use IS the freshness anchor (no separate nonce needed, unlike §5.14.13's grant_nonce).
- CAVEAT noted in assessment: destroy must be implemented strictly downstream of join Ok (one ordering: join consumes → join Ok → destroy). Collision-resolution orchestration NOT YET in runtime actor (Phase-2E pending); spec specifies required ordering. `destroy_group` primitive exists (group.rs:502).

**Phantom-backstop correction (ACCURATE).** Injectivity invariant now states colon-join was ALWAYS sole isolation anchor for `derived_context_id`; #1811-removed `group_id` was the SAGA's MLS group identifier, not an isolation co-anchor. Verified: MLS isolation keys on `Entry::Vacant` guard over `SHA-256("standing-"‖hex(derived_context_id))` (provider.rs:743 `contexts.entry`). OpenMLS random GroupId is per-create, never an isolation key. Length-prefix hardening (§9.5.1 len32-framing) correctly framed as retiring a human method-admission-review gate (unconditional injectivity), NOT recovering a lost backstop. Recommended follow-up, deliberately deferred (coordinated spec+code change).

**Credential-bound check (SOUND).** Creator-credential confirm requires BOTH leaf ScpCredential.did==did_lo AND leaf MLS sig key == VM resolved from did_lo's DID doc (§9.7.1, credential.rs resolves #active/#agent VM publicKeyMultibase). Forecloses forged-creator-string DoS + targeted-teardown DoS.
