# ADR-057 T1 — scp-primitives dissolution / scp-did extraction (crypto topology)

Reviewed range 86519aa6f..81ef76c56 (branch refactor/dissolve-primitives-split-identity). VERDICT: SOUND, behavior-preserving.

## New crate homes (post-split)
- `scp-crypto` (leaf) — `verify_ed25519_signature` (uses `verify_strict`, malleability-rejecting). Verbatim from scp-primitives/crypto.rs. Consumers import `scp_crypto::verify_ed25519_signature` directly (event-log, runtime scpid, protocol trust/challenge/claiming/attestation). Old re-export shims scp-event-log/src/crypto.rs + scp-protocol/src/crypto/ed25519.rs DELETED.
- `scp-clock` (leaf) — `Clock`/`SystemClock`/`TestClock`. Verbatim from scp-primitives/time.rs. epoch_grace.rs (stays in scp-mls) now imports `scp_clock::{Clock,SystemClock}`.
- `scp-did` (leaf, wasm-safe) — DID data model: `DID`, `SigningKeyId`, `extract_public_key_from_did`, `DidDocument`, `VerificationMethod`, `MigrationProof`, `PreRotationProof`, `Service`, `decode_multibase_key`, `DidError` (renamed from `DidDocumentError`), `attestation` module. Deps: ed25519-dalek DIRECTLY (no scp-crypto edge — pure leaf), serde/serde_json/serde_bytes/hex/base64/bs58/z-base-32/thiserror. Curve validation via `ed25519_dalek::VerifyingKey::from_bytes` in decode_multibase_key.
- scp-primitives crate FULLY DISSOLVED (dir + workspace member gone).

## Equivalence verified
- crypto.rs/time.rs: verbatim + only crate-header attrs added.
- identity.rs→lib.rs: zero body changes; only module docs + `pub mod`/`pub use`. SigningKeyId as_fragment/from_fragment strict (#active/#agent only), canonical bytes byte-identical. 121 scp-did tests pass (incl msgpack/JSON serde roundtrips pinning preimage/wire).
- document.rs + attestation.rs: pure `DidDocumentError`→`DidError` rename + import-path fixes. Signed/hashed structs, base58btc decode, curve validation byte-identical.
- `impl From<scp_did::DidError> for IdentityError` (scp-identity/src/lib.rs:357): variant-for-variant, payload-preserving, complete (all 7 variants). Behavior-preserving, not just compile-preserving.
- MLS credential path: `scp_protocol::identity::document::{...}`+`scp_primitives::SigningKeyId` → `scp_did::{DidDocument,SigningKeyId,decode_multibase_key}`. Same types.
- Fuzz differentials + templates/scaffolds: import-source retarget only.
- No-shim gate scripts/check-no-shim-reexports.sh = positive closed check over {scp_clock,scp_crypto,scp_did,scp_mls}. No shim re-exports found. No dangling DidDocumentError/scp_protocol::identity::document refs.
- Builds: scp-mls/scp-protocol/scp-identity OK; scp-event-log 200 tests pass (needs --features testing per did:key gating).

## OPEN (pre-existing, NOT introduced by split; tracked to T1c) — z-base-32 parser strength gap
Two `did:dht:z…` parsers with a real MALLEABILITY difference:
- `scp_identity::dht::extract_public_key` (dht.rs:2728) — STRONG: re-encodes decoded key + rejects non-canonical trailing-bit-padding (round-trip check). Test extract_public_key_rejects_non_canonical_zbase32_padding.
- `scp_did::extract_public_key_from_did` (scp-did/src/lib.rs:120) — WEAK: NO canonicality check. Multiple DID strings decode to same pubkey.
Consumers of WEAK parser (all used weak scp_primitives version before too — no regression): scp-event-log/src/tree.rs:320, scp-protocol/bridge/claiming.rs:210/223, scp-protocol/trust/attestation.rs:635.
ADR-057 T1c bullet (line 86) accurately documents this + mandates: port canonicality check INTO scp_did FIRST, then consolidate on the hardened scp-did parser (must not adopt weaker). ADR text is correct.
