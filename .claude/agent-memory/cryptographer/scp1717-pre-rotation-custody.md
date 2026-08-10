---
name: scp1717-pre-rotation-custody
description: SCP-1717 pre-rotation custody + DID migration review through round-10 (SOUND, no blocking findings); open MEDIUMs, fixed LOWs, rotated_at bounds, cross-bridge commitment invariant
metadata:
  type: project
---

# SCP-1717 pre-rotation custody — round-10 final review (2026-05-10): SOUND, no blocking findings

## Round-10 (commit `7ce74e7ca`)

Added 6 typed FFI error codes `SCP-IDENT-1047..1052`, one per `PreRotationCustodyError`
variant. Diff confined to PyO3/NAPI/UniFFI `From<IdentityError>`; zero crypto substrate
drift (`git diff -- scp-identity scp-platform scp-ffi/wasm` empty). Byte-equal
const-string mapping across the 3 bridges; 7 regression tests pin variants + fallback.
WASM intentionally unchanged (own registry, `IDENT_1002`).

LOW followups: parity codes in WASM custody paths; rustdoc warning to backend
implementers about not embedding key material in
`Storage`/`Unavailable`/`InvalidCallbackResponse` strings.

## Round-8 polish

- Kotlin `Identity.migrate` deprecation `level = ERROR` (`Identity.kt:299-308`).
- `bind_old_document_to_old_did`'s 5 error paths uniformly map to
  `MigrationVerificationFailed` (`dht.rs:1919-1948`).
- Step-0 mismatch error carries 12-byte hex prefixes for the did-derived and
  document-derived pubkeys (`dht.rs:1940-1946`).
- CI clippy clean at full feature set.
- Prior HIGH (`verify_migration` old_public_key → old_did binding via step 1b)
  addressed: `bind_old_document_to_old_did` is now an explicit Step 0 backstop.
  Caller contract explicit at `dht.rs:2023-2036` (must use `resolve_did` /
  `verify_and_deserialize` / `relay_resolve`).

## Construction details

- `rotated_at` bounds (`dht.rs:1809-1840`): `MAX_FUTURE_SKEW_SECS = 300`,
  `MAX_PAST_WINDOW_SECS = 5y`, `MIGRATION_EPOCH_FLOOR_UNIX_SECS = 1_700_000_000`
  (hard floor closes the saturating-clamp loophole on broken-clock verifiers).
- `check_rotated_at_window` boundary walk: `rotated_at = floor` passes, `floor-1`
  rejected, `u64::MAX` rejected (when now is real); `now = 0` → floor still rejects
  `rotated_at < floor`.
- Step ordering: probe → reveal → build proofs → generate-new-pre-rot → store-new →
  destroy-old/import-as-`#0` → build-doc → publish-NEW → publish-OLD-with-aKa.
- Step 0 probe (`import_ed25519_signing_key` + `destroy_key`) catches `Unsupported`
  pre-flight; `FileKeyCustody` dedup ensures the probe doesn't append duplicate file
  entries (concurrent dedup test exists).
- ADR-046 byte parity preserved (seed `[0..32]` = identity, `[32..64]` = active,
  `[64..96]` = pre-rotation, `[96..128]` = agent).
- z-base-32 canonicality math: 32 bytes → 52 chars + 4 padding bits in the last char
  → 16 alternates; encode-and-compare rejects all.
- `ed25519_dalek::SigningKey` 2.2.0 impls `ZeroizeOnDrop` — drops at line 1273 wipe internals.
- All 4 bridges have a `SHA-256(revealed_key) == commitment` cross-bridge invariant
  test on REAL bridge output (UniFFI 15384, NAPI 1518, PyO3 2150, WASM 5072).
- Reverse-parity test (WASM `tests/native_emitted_rotation_event_json_matches_wasm_encoding`):
  value-equality + native-deserialize round-trip + byte-canonicalize compare — strong.
- WASM `pre_rotation_commitment` recomputed from `revealed_key` (= old pre-rot pub);
  the verifier later checks it against the old doc's service entry — equivalent to native.
- 268 scp-identity tests pass (1 `#[ignore]`); 96 scp-platform tests pass.

## Fixed LOWs

- Probe seed now `OsRng`-derived (`dht.rs:1258-1260`) — collision probability ~2^-256.
  Was `[0u8; 32]` in an earlier rev.
- `PreRotationKeyEntry` struct-level `Zeroize` derive at
  `testing/pre_rotation_custody.rs:40` + WASM mirror at `wasm/identity.rs:441`.
- `retire_operational_keys_for_migration` (`document.rs:890-913`) now uses exact-fragment
  match via `rsplit('#').next()`. Test at `document.rs:2444` injects `#secondary-active`
  and verifies retention.
- `from_did` Local-record preservation test at `wasm/identity.rs:5442` — idempotent
  re-call preserves `IdentityRecord::Local` + `custody_type` + `agent_signing_key_bytes`.

## Open

- LOW: WASM z-base-32 parity test pinned to 3 vectors (`wasm/identity.rs:5950`) —
  replace with a proptest over 1000+ random 32-byte inputs.
- LOW/MEDIUM (2026-05-03): `verify_migration` doesn't bind `old_document` to `old_did`
  (no internal check that `old_document.id == old_did`, or that the `#0` VM derives
  `old_did`). A caller-supplied document allows a STRONG-bypass: an attacker with the
  compromised `#0` private key can supply a forged `old_document` with no
  `PreRotationCommitment` service, defeating the STRONG-when-committed enforcement at
  step 1c. Mitigated when the caller uses `resolve_did` (which calls
  `verify_self_certification`). DOCUMENTATION GAP — the caller contract is not stated in
  rustdoc. Recommended inline fix: extract `expected_id_pk` from `old_did`, decode the
  `#0` VM's `public_key_multibase`, and compare inside `verify_migration`. HIGH if any
  production caller skips resolution; MEDIUM with the documented contract.
- MEDIUM: `CallbackKeyCustody.import_ed25519_signing_key` returns `Unsupported`
  (production iOS/Android `migrate` fails fast at step 0 — no leak, but a feature
  blocker for #1729).
- MEDIUM: callback substrate isolation incomplete (`OsRng` in the bridge process holds
  bytes briefly co-resident with operational keys).
- MEDIUM: step-7 `publish_document(new)` failure leaves the new identity uninstalled
  with a consumed old pre-rotation key — returns `Err` with no recovery handle.
