---
name: bridge-relay-auth-and-crypto22-s4
description: Bridge relay auth + DID healing (PR #255, SCP-247/245) and the CRYPTO-22 S4 KeyPackage-attestation verifier seam — both SOUND
metadata:
  type: project
---

# Bridge relay auth + DID healing (PR #255, SCP-247/SCP-245)

- Bridge auth preimage: `"SCP-BRIDGE-REGISTER-V1:" || routing_id[32] || be_u64(timestamp)` = 63 B fixed — SOUND
- `verify_strict()` used; verification order timestamp → sig → routing_id (fast-reject)
- Routing ID: `SHA-256("scp:did:" || did_string)` — domain-separated, golden vector verified
- DID derivation: `did:dht:z` + zbase32(pubkey) — deterministic, invertible
- 60 s replay window, no nonce tracking — acceptable (idempotent registration)
- `DualLayerResolver`: `tokio::join!`, BEP44 `verify_strict` on both layers, anti-rollback via cached seq
- Healing: async best-effort republish to the stale layer, panic-monitored
- PRE-EXISTING: the migration proof hash (dht.rs:607) has a variable-length concat ambiguity (`old_did || new_did`)

# CRYPTO-22 S4 KeyPackage-attestation seam (crypto22-s4-code, e51741b6)

- Layer B `verify_add_attestation` (attestation_verification.rs, renamed from `verify_add_or_update_attestation`): async resolver seam. `resolved_at = clock.now_secs()` BEFORE resolve, `now = clock.now_secs()` AFTER; fail-closed on `Err`/`None` (no stale fallback); delegates to the pure Layer-A `verify_attestation_with_resolution` (checks 2, 1, then 3-13).
- e51741b6 delta vs 3872f57da = Add-only NARROWING: new `AttestationAddGroundTruth` (no trigger field, carries `kp_init_key`); the wrapper builds `AttestationTrigger::Add{kp_init_key}` INTERNALLY as a 1:1 field-map into `AttestationLeafGroundTruth`. `Update` is now unrepresentable at this seam by construction (was fail-closed-no-grace before → no behavior regression, strictly tighter). Pure core UNCHANGED (no diff to `verify_attestation_with_resolution`). Key resolution by `signing_key_id` + sig-binding all live in the unchanged pure core. Checks 7-8 get the correct `init_key`.
- Tests: Layer-B rotation-reject (resolved #active = fresh_pub → check 3 `SignatureInvalid`, proves the resolved doc drives check 3, §9.12 rotation-is-revocation); Layer-B `SteppingClock[NOW, NOW+400]` pins `resolved_at` to the EARLIER read (age 400 > 300 → `ResolvedDocumentStale`); Layer-A #agent persona (agent_fixture: unrelated #active discriminator, resolves the credential-named #agent VM → `Ok`; missing → `CurrentKeyNotFound`). SOUND, no regression, shipped.
