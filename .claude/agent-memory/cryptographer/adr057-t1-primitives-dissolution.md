---
name: adr057-t1-primitives-dissolution
description: ADR-057 T1 crypto-crate split review (dissolve scp-primitives → scp-crypto/scp-clock/scp-did) — verbatim-move verification, all SOUND
metadata:
  type: project
---

# ADR-057 T1: dissolve scp-primitives, extract scp-did (branch refactor/dissolve-primitives-split-identity, HEAD 280983dd7)

Reviewed range 86519aa6f..HEAD. Crypto verdict: **SOUND, no blocking findings.** Every crypto move is verbatim or a pure import-repoint to an identical type.

**Why:** big topology refactor moving crypto between crates; needed cryptographic-equivalence verification at every moved site.

**How to apply:** if re-reviewing this branch or its T1c/T2 successors, these equivalences are already established — focus new review on *newly written* code (T1c ports canonicality check + BEP44 helper move), not re-verifying T1 moves.

## Verified equivalences
- `scp-crypto/src/lib.rs` = old `scp-primitives/crypto.rs` 98% (header only). `verify_ed25519_signature` → `verify_strict` (cofactorless, small-order reject), 32/64-byte length checks intact.
- `scp-clock/src/lib.rs` = old `scp-primitives/time.rs` 98% (header only). Clock/SystemClock/TestClock verbatim. epoch_grace.rs (stays in scp-mls) just repoints `scp_primitives::{Clock,SystemClock}`→`scp_clock::` — GRACE_WINDOW_MILLIS/now_millis unchanged.
- `scp-did/src/lib.rs` = old `scp-primitives/identity.rs` 93% (header + `pub mod attestation/document` + re-exports). DID/SigningKeyId/extract_public_key_from_did verbatim. SigningKeyId fragment preimages verbatim: as_fragment "#active"/"#agent", fragment "active"/"agent", as_bytes b"#active"/b"#agent", from_fragment strict.
- `scp-did/src/document.rs` = old `scp-protocol/identity/document.rs` 96% — pure rename DidDocumentError→DidError + `super::did_attestation`→`super::attestation`. base58btc alphabet, decode_multibase_key VerifyingKey::from_bytes curve check, all rotation/migration proof methods byte-identical.
- `scp-did/src/attestation.rs` = old `scp-protocol/identity/did_attestation.rs` 97% — same rename only.
- DidError↔IdentityError completeness: DidError has EXACTLY 7 variants (InvalidDidFormat, DocumentSerializationError, DocumentDeserializationError, InvalidRelayUrl, AgentKeyAlreadyExists, AgentKeyNotFound, MultipleAgentKeys) — all 7 covered by `impl From<scp_did::DidError> for IdentityError` in scp-identity.
- scp-event-log: deleted crypto.rs+time.rs re-export shims; tree.rs imports `scp_crypto::verify_ed25519_signature` + `scp_did::extract_public_key_from_did` directly (same weak parser as before — no strength change). KAT vectors 32/33 (checkpoint root) PASS byte-stable.
- scp-mls credential.rs: import repoint to `scp_did::{DidDocument,SigningKeyId,decode_multibase_key}`. Credential preimage unchanged.
- Fuzz differentials: pure import repoints, fuzzed logic unchanged.

## Empirical
- `cargo build -p scp-crypto -p scp-clock -p scp-did -p scp-event-log` clean.
- `cargo build ...--target wasm32-unknown-unknown` clean for all 3 leaf crates (wasm fence holds; did:key hex gated out of non-testing builds).
- Tests pass: scp-crypto/scp-did/scp-event-log incl. KAT 32/33.

## ADR claims verified TRUE of code
- **T1c parser-canonicality directive:** `scp_identity::dht::extract_public_key` (dht.rs:2728) DOES the z-base-32 canonicality round-trip check (re-encode + compare, closes trailing-bit-padding non-injectivity); `scp_did::extract_public_key_from_did` (lib.rs) does NOT (bare zbase32::decode + len check, not even a curve check). Pre-existing divergence, correctly flagged for T1c to port-then-consolidate. NOT introduced/regressed by T1 (event-log used the weak parser before AND after).
- **BEP44 inventory:** all 6 external `bep44_signable` callers match ADR exactly (scp-ffi/src/identity.rs:164, scp-ffi/napi/src/identity.rs:173, scp-ffi/uniffi/src/bridge.rs:20678, scp-ffi/common/src/resolvers.rs:1163, scp-ffi/napi/src/tools.rs:1974, scp-node/src/self_host.rs:2664) + lib.rs:49 re-export of verify_bep44_signature. No external consumer of the re-exported verify_bep44_signature.

## Pre-existing (NOT this change set, deferred to T1c)
- z-base-32 non-injective trailing-bit-padding: scp_did parser accepts non-canonical did:dht:z… spellings → DID-aliasing risk if DID strings used as identity keys. For event-log signature verification it's benign (key bytes still correct). ADR T1c directs the fix.
