---
name: SCP-1717 pre-rotation key retention review
description: Findings from reviewing 19bd8ccba/8a8bf4544/753d461b2 — pre-rotation key retention on ScpIdentity to satisfy spec §3.7 SHA-256 invariant
type: project
---

## Confirmed bugs in 3-commit pre-rotation retention fix

1. **HIGH — PersistedIdentity backward-compat break (scp-node).** Adding non-Option `pre_rotation_key: KeyHandle` to ScpIdentity (which derives Serialize/Deserialize and is wrapped by scp-node's PersistedIdentity persisted via rmp-serde named format under "scp/identity") causes ALL pre-fix persisted identities to fail deserialization with "missing field". CURRENT_STORE_VERSION (=2) was NOT bumped. No Migratable impl. validate_persisted_custody doesn't validate the new field. scp-node tests use the new field — they don't pin pre-fix wire format.

2. **LOW — WASM `from_did` doc-comment lies about error code.** docstring says SCP-IDENT-1000 for non-did:dht prefix; code returns IDENT_1004 (key generation failed). IDENT_1000 is "generic identity error". Same issue: doc says IDENT_1004 for non-32-byte payload (correct); the bigger issue is the prefix-error code.

3. **LOW — WASM `from_did` skips registry capacity check.** WasmIdentity::from_did inserts into IDENTITY_REGISTRY via or_insert_with WITHOUT calling check_registry_capacity. Every other insertion site (identity_create, etc.) checks WASM_IDENTITY_REGISTRY_CAP=10_000. Same-origin DoS via 10_001+ from_did calls.

4. **LOW — UniFFI bridge has no migrate test asserting SHA-256(revealed)==commitment.** PyO3, NAPI, WASM all assert this invariant. UniFFI does not. The fix-claim "Caught by adding the SHA-256 invariant assertion to NAPI + PyO3 migrate tests" is true but UniFFI was not extended with the same gate.

5. **LOW — pre_rotation_proof: None case never tested for cross-bridge JSON parity.** New reverse-parity test only covers Some. Native code path always emits Some, WASM always emits an object (never null). If a third-party tool produces None, native serializes as `"pre_rotation_proof": null`, WASM cannot. Theoretical.

## Confirmed correct (no defect)

- KeyHandle copy-then-pass-by-ref pattern in tests is fine (KeyHandle = u64 wrapper, Copy, no Drop).
- temp_new_identity in migrate_identity correctly uses old pre_rotation_key as new identity_key (it BECOMES the new #0 per spec).
- KeyHandle::new(0) stub in test ScpIdentity literals — these never reach custody operations.
- create_new_identity_keys signature change applied at the only call site (line 1180 in dht.rs).
- WASM `from_did` or_insert_with correctly leaves Local records intact.
- Native + WASM both use lowercase hex via `hex::encode`; cross-bridge parity holds.

## Pre-existing issues (not introduced by these commits)

- WASM zbase32 encoder leaves 4 unused bits in the 52nd char → multiple distinct strings decode to same bytes. Native `zbase32::decode` (third-party crate) may behave differently. Could enable from_did(did1) and from_did(did2) registering separate Resolved entries with same public key.
