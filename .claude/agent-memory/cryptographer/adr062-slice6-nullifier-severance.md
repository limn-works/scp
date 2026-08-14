---
name: adr062-slice6-nullifier-severance
description: ADR-062 Slice 6 / SCP-CAPINJECT-006 — fail-closed prod identity creation + severance of all 4 in-memory nullifiers (custody/attestation/pre-rotation/DHT) to test-harness-only. Crypto SOUND.
metadata:
  type: project
---

# ADR-062 Slice 6 nullifier severance (branch feat/adr062-slice6-nullifier-severance, 554994606)

VERDICT: cryptographically SOUND, no blocking findings. Reviewed 2026-07-16.

Core lever: `DidMethod::create`/`create_with_agent_key`/`migrate_identity` signatures UNCHANGED — still require `&impl PreRotationCustody`. The pre-rotation COMMITMENT is computed INSIDE those fns from `pre_rotation_custody.commit(...)`, so "no commitment without backing custody" is TYPE-ENFORCED (can't call create without passing a custody). In prod no caller passes one → fails closed before the call.

Fail-closed ordering CLEAN (no partial state): every create funnel returns `Err(NoPreRotationBackend)` / `no_pre_rotation_backend()` (IDENT_1059; attestation uses IDENT_1010) in the `#[cfg(not(feature="testing"))]` arm, which is a pure early-return with NO `did_method.create` (keygen), NO commitment, NO registry write, NO persist, NO DHT publish. The `#[cfg(feature="testing")]` arm holds the mint flow. Mutually-exclusive cfg blocks; prod compiles only the Err arm. Verified in config.rs create_inner, pyo3 identity.rs (identity_create/with_agent_key/with_custody), uniffi bridge.rs (5 create + rotate/migrate sites), napi identity.rs, scp-node lib.rs (resolve_identity + resolve_identity_persistent — Err before keygen AND before storage.store).

`IdentityEntry.pre_rotation_custody` field is `#[cfg(feature="testing")]` → compiler FORBIDS any non-testing construction of IdentityEntry (sibling gated field), so no shipped path builds an entry; prod registry always empty → lookups fail closed. `pre_rotation_handle` field ungated but only reachable via (gated) construction.

Custody: FfiKeyCustody::InMemory variant `#[cfg(feature="testing")]`; prod enum = File (Argon2id+AES-256-GCM) + Callback (platform keychain) only. "in_memory" custody string rejected in non-testing parse_custody. No key in weaker store.

Attestation: identity_verify_device_attestation_impl `#[cfg(not(testing))]` returns Err (IDENT_1010), NEVER Ok(true) — cannot coerce forged attestation. identity_verify_link_attestation (§3.5.1) is real Ed25519 verify_signature, correctly UNTOUCHED.

server.rs (Group E): InMemoryKeyCustody→FileKeyCustody is a PHANTOM type annotation on IdentitySource::Explicit (carries no custody); no runtime key-store change. start_node_in_memory None-arm → ServerError::AutoGenerateUnavailable (fail closed, not panic).

Mechanical enforcement: Cargo.toml removes `scp-platform/testing` from unconditional dep lines of scp-ffi/napi/scp-identity/scp-node, folds into each crate's own `testing` feature. G1 gate scripts/check-shipped-feature-graph.sh = per-package (`cargo tree -e features,no-dev -p CRATE --no-default-features --features server`), positive ⊆-whitelist (durability-only, ZERO nullifier features, self-test asserts it), dev-deps excluded so scp-identity dev-dep scp-platform/testing doesn't leak. RAN: G1 real gate PASSES all 3 bridges; self-test fixtures + positive controls pass; scp-identity builds clean shipped mode.

INFO (non-findings): (1) in-memory-storage stays shipped — durability-only dev affordance, stores public DID docs/protocol state, never private keys (custody boundary + EncryptedStorage bound); not a nullifier. (2) scp-node resolve_identity_persistent step-2 LOAD path ungated — dead in pure prod (nothing persisted since create fails closed); a cross-build shared data_dir could load+OPERATE a testing-created identity, but operating (signing) needs no pre-rotation; pre-existing migration-impossible limitation, not a new downgrade. (3) config.rs uses `any(test, feature="testing")` (test disjunct for scp-identity's own unit tests, dev-dep supplies scp-platform/testing) — safe: cfg(test) never set in shipped artifacts, G1 checks --no-default-features so test-only path never ships.
