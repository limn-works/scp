---
name: scp1717-pre-rotation-custody
description: SCP-1717 pre-rotation custody review through round 10 — sound, with the remaining open MEDIUM and LOW items
metadata:
  type: project
---

# SCP-1717 pre-rotation custody (round-10 final review, 2026-05-10) — SOUND, no blocking findings

## Round 10 (commit 7ce74e7ca)

Added 6 typed FFI error codes SCP-IDENT-1047..1052, one per
`PreRotationCustodyError` variant. Diff confined to PyO3/NAPI/UniFFI
`From<IdentityError>`; zero crypto substrate drift (`git diff -- scp-identity
scp-platform scp-ffi/wasm` empty). Byte-equal const-string mapping across all 3
bridges. 7 regression tests pin variants plus fallback. WASM stayed unchanged on
purpose (own registry, IDENT_1002). LOW followups: parity codes in WASM custody
paths; a rustdoc warning telling backend implementers not to embed key material
in Storage/Unavailable/InvalidCallbackResponse strings.

## Round 8 and earlier

- Kotlin `Identity.migrate` deprecation level=ERROR (Identity.kt:299–308).
- `bind_old_document_to_old_did`'s 5 error paths map uniformly to
  `MigrationVerificationFailed` (dht.rs:1919–1948); step-0 mismatch error carries
  12-byte hex prefixes for did-derived and document-derived pubkeys
  (dht.rs:1940–1946).
- CI clippy clean at full feature set (`allow_in_memory_custody` on all bridges
  plus scp-core/scp-runtime testing).
- Prior HIGH (`verify_migration` old_public_key → old_did binding via step 1b)
  addressed: `bind_old_document_to_old_did` is now an explicit Step 0 backstop.
  Caller contract explicit at dht.rs:2023–2036 (must use `resolve_did` /
  `verify_and_deserialize` / `relay_resolve`).
- `PreRotationKeyEntry` struct-level `Zeroize` derive FIXED at
  testing/pre_rotation_custody.rs:40 plus a WASM mirror at wasm/identity.rs:441.
- `rotated_at` bounds at dht.rs:1809–1840: `MAX_FUTURE_SKEW_SECS=300`,
  `MAX_PAST_WINDOW_SECS=5y`, `MIGRATION_EPOCH_FLOOR_UNIX_SECS=1_700_000_000`
  (a hard floor closing a saturating-clamp loophole on broken-clock verifiers).
  Boundary walk: `rotated_at=floor` passes, `floor-1` rejected, `u64::MAX`
  rejected when now is real; with `now=0` that floor still rejects
  `rotated_at < floor`.
- Step ordering: probe → reveal → build proofs → generate new pre-rotation →
  store new → destroy old / import as #0 → build doc → publish NEW → publish OLD
  with aKa.
- Step 0 probe (`import_ed25519_signing_key` + `destroy_key`) catches
  `Unsupported` pre-flight; FileKeyCustody dedup keeps that probe from appending
  duplicate file entries (a concurrent dedup test exists). Probe seed is now
  OsRng-derived (dht.rs:1258–1260), so collision probability against any
  pre-existing entry is ~2^-256; it was `[0u8;32]` in an earlier revision.
- `retire_operational_keys_for_migration` (document.rs:890–913) uses exact
  fragment match via `rsplit('#').next()`. Test at document.rs:2444 injects
  `#secondary-active` and verifies retention.
- `from_did` Local-record preservation test at wasm/identity.rs:5442: an
  idempotent re-call preserves `IdentityRecord::Local`, custody_type, and
  agent_signing_key_bytes.
- All 4 bridges carry a `SHA-256(revealed_key) == commitment` cross-bridge
  invariant test on REAL bridge output (UniFFI 15384, NAPI 1518, PyO3 2150,
  WASM 5072).
- Reverse-parity test (WASM
  `tests/native_emitted_rotation_event_json_matches_wasm_encoding`): value
  equality plus native-deserialize round trip plus byte-canonicalize compare.
- WASM `pre_rotation_commitment` recomputed from `revealed_key` (the old
  pre-rotation public key); a verifier later checks it against the old document's
  service entry — equivalent to the native flow.
- ADR-046 byte parity preserved: seed[0..32] identity, [32..64] active,
  [64..96] pre-rotation, [96..128] agent.
- zbase32 canonicality math: 32 bytes → 52 chars plus 4 padding bits in the last
  char → 16 alternates; encode-and-compare rejects all of them.
- `ed25519_dalek::SigningKey` 2.2.0 implements `ZeroizeOnDrop`, so drops at
  line 1273 wipe internals.
- 268 scp-identity tests pass (1 `#[ignore]`); 96 scp-platform tests pass.

## Open items

- LOW: WASM zbase32 parity test pinned to 3 vectors (wasm/identity.rs:5950) —
  replace with a proptest over 1000+ random 32-byte inputs.
- LOW (2026-05-03): `verify_migration` does not bind `old_document` to
  `old_did` — no internal check that `old_document.id == old_did`, nor that its
  #0 VM derives `old_did`. A caller-supplied document permits a STRONG-bypass:
  an attacker holding the compromised #0 private key supplies a forged
  `old_document` carrying no `PreRotationCommitment` service, defeating
  STRONG-when-committed enforcement at step 1c. Mitigated when a caller uses
  `resolve_did`, which calls `verify_self_certification`, but that caller
  contract is not stated in rustdoc. Recommended fix inside `verify_migration`:
  `let expected_id_pk = extract_public_key(old_did)?;`
  `let doc_pk = decode_multibase_key(&old_document.verification_method_by_fragment("0")?.public_key_multibase)?;`
  `if doc_pk != expected_id_pk { return Err(...); }`.
  Severity HIGH if any production caller skips resolution; MEDIUM with the
  documented contract.
- MEDIUM: `CallbackKeyCustody.import_ed25519_signing_key` returns `Unsupported`,
  so production iOS/Android migrate fails fast at step 0 — no leak, but a feature
  blocker for issue #1729.
- MEDIUM: callback substrate isolation incomplete — OsRng in a bridge process
  holds bytes briefly co-resident with operational keys.
- MEDIUM: a step-7 `publish_document(new)` failure leaves a new identity
  uninstalled with a consumed old pre-rotation key, and that function returns
  `Err` with no recovery handle.
