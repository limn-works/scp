# Cryptographic Invariants Must Be Asserted On Every Bridge, Not Just Named in the Matrix

> **ADR-055 (2026-06-29):** the WASM bridge was removed; the SCP-1717 incident narrative below references a fourth WASM/wasm-bindgen bridge (which happened to be the reference that re-asserted the invariant) as historical fact. There are now three bridges (PyO3, NAPI, UniFFI); the browser is a remote thin client. The rule — every cryptographic invariant must be re-asserted, in bytes, on every bridge that emits the artifact — remains evergreen across the three remaining bridges.

**Date:** 2026-04-27
**Source:** SCP-1717 — three native bridges (PyO3, NAPI, UniFFI) silently emitted invalid pre-rotation proofs because only the WASM bridge re-asserted the spec §3.7 `SHA-256(revealed_key) == commitment` invariant.

## Rule

Every spec-defined cryptographic invariant carried by a wire artifact must be re-asserted, in bytes, on every bridge that emits that artifact. Matrix-name parity (the operation is exposed under the right name in `scripts/bridge-aliases.json` and `ffi_conformance.rs`) is necessary but not sufficient — it proves the surface is symmetric, not that the output satisfies the protocol contract.

## What went wrong

`migrate_identity` was registered as a parity operation across all four bridges. `ffi_conformance.rs` was green. Each bridge's `migrate` test asserted only `event.pre_rotation_proof.is_some()`.

The native bridges (PyO3, NAPI, UniFFI) all generated a *fresh* pre-rotation key at migrate time because the original pre-rotation key was destroyed in `create_new_identity_keys` per a literal reading of spec §9.7.4.1 #5f ("destroy from memory after backup is confirmed"). The fresh key's hash never matched the published commitment — `verify_migration` would correctly reject every native-emitted rotation event. The WASM bridge stashed its pre-rotation key in a thread-local registry and so emitted valid proofs.

The bug class was invisible to the bridge-symmetry harness because every bridge had `migrate_identity` under the same canonical name. The bug surfaced only after porting WASM's `SHA-256(revealed_key) == commitment` assertion to NAPI and PyO3 tests — both immediately red.

## The pattern that catches it

For every wire artifact that carries a cryptographic invariant, each bridge's own test suite must:

1. Invoke the bridge end-to-end (no internal-only mocks).
2. Deserialize the emitted bytes back to the cross-bridge wire type.
3. Re-run the invariant computation on the deserialized fields.
4. Assert byte equality, not just `is_some()` / `non_empty()`.

Concrete example from the SCP-1717 fix (mirrored across all four bridges — PyO3, NAPI, UniFFI, and WASM):

```rust
let pre_rot = event.pre_rotation_proof.as_ref().expect("MUST be present");
use sha2::{Digest, Sha256};
let recomputed: [u8; 32] = Sha256::digest(pre_rot.revealed_key).into();
assert_eq!(
    recomputed, pre_rot.commitment,
    "PreRotationProof MUST satisfy SHA-256(revealed_key) == commitment"
);
```

## Reverse-direction parity

Commit 753d461b2 also added `native_emitted_rotation_event_json_matches_wasm_encoding`: the native serde serialization of `DidRotationEvent` MUST be structurally identical to the WASM `encode_rotation_event_json` output, and WASM JSON MUST round-trip through the native struct. Generalizes: when two bridges encode the same wire type, parity must be tested in both directions, not just "WASM matches native" or "native matches WASM" — drift on either side breaks interop.

## Where to encode the rule

Add to `CLAUDE.md` Integration checklist as item 6:

> For any operation that emits a wire artifact carrying a spec-defined cryptographic invariant, every bridge that emits the artifact MUST have a behavioral assertion that recomputes the invariant from the emitted bytes. Matrix-name parity is not sufficient.

## Related

- `.docs/lessons/cross-bridge-canonical-naming.md` — covers name parity (necessary), this lesson covers byte parity (also necessary, complementary).
- `.docs/lessons/pre-rotation-key-must-be-stored-at-creation.md` — covers the storage half of this specific bug (preimage lifetime). This lesson covers the test-coverage half.
- ADR-003 §4b (`.docs/adrs/phase-1.md` lines 348-415) — the migrate operation contract.
- spec §3.7 — the `SHA-256(revealed_key) == commitment` invariant.
- `scripts/bridge-aliases.json`, `crates/scp-testing/tests/integration/ffi_conformance.rs` — surface symmetry; do not validate behavioral parity.
