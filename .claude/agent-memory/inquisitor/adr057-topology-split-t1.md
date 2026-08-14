---
name: adr057-topology-split-t1
description: ADR-057 T1 crate-topology split (dissolve scp-primitives → scp-clock/scp-crypto/scp-did) — as-built verdict, enforcement map, T1c inventory
metadata:
  type: project
---

ADR-057 Amendment T1 (branch refactor/dissolve-primitives-split-identity, HEAD d2a783a55): dissolved
`scp-primitives` into capability leaves and extracted the wasm-safe DID data model.

**Verdict: SOUND.** Decisions well-grounded; ADR unusually rigorous and self-honest. Reviewed the
full 86519aa6f..HEAD range + ADR in full.

**As-built facts (verified against tree, for future passes):**
- `scp-primitives` fully GONE (zero residual refs).
- Leaves: `scp-clock` (zero-dep leaf), `scp-crypto` (ed25519-dalek only), `scp-did` (ed25519-dalek +
  serialization; **no scp-crypto edge** — does curve-point `from_bytes` only, NOT signature verify).
- `scp-did` owns DID data model + `DidError`; DidDocument now ONLY in `crates/scp-did/src/document.rs`.
  Interim Slice-1a strays (scp-protocol identity/document.rs + did_attestation.rs) fully removed.
- `scp-protocol/src/identity/attestation.rs` (`IdentityLinkAttestation`, imports `scp_did::DID`)
  INTENTIONALLY stays — flagged honestly in ADR §101 as protocol-wire residue, not a stray.
- Proof VERIFICATION (verify_migration/verify_self_certification) lives in scp-identity/src/dht.rs,
  NOT scp-did. scp-did owns proof data structures only. This is why no scp-crypto edge is needed.

**Enforcement map (all wired, verified):** acyclicity=rustc; wasm fence=ci.yml:338 (`cargo check -p
scp-clock -p scp-crypto -p scp-did -p scp-protocol -p scp-mls -p scp-client-wasm --target
wasm32-unknown-unknown`); banned-dep=check-protocol-deps.sh (guards scp-protocol tree only);
no-shim=check-no-shim-reexports.sh (closed set {scp_clock,scp_crypto,scp_did,scp_mls}, scp-core
facade exempt, registered in CLAUDE.md). Gate honestly documents its rustfmt-coupling.

**T1c (future, NOT done):** dht_client/ (mod.rs=DhtClient trait+DhtRecord+in-mem; pkarr_client.rs)
still in scp-identity. Inventory in ADR §86 all verified accurate: 6 out-of-crate bep44_signable
callers match exactly; pkarr calls crate::dht::verify_bep44_signature; lib.rs re-exports it; dual
extract_public_key parsers (scp_did::extract_public_key_from_did + scp_identity::dht::extract_public_key)
both exist. scp_dht NOT yet in no-shim gate set (correct).

**Coherence residue from 4 editing rounds (all LOW, none load-bearing):**
1. §83 "Two corrective slices" but THREE bullets (T1/T1c/T2) — T1c inserted in a later round, count
   never updated. Also T1 (this changeset, landed) is listed among slices that "follow."
2. Diagram §114-121 draws scp-clock/scp-crypto as leaves with NO downstream edges — attributes the
   whole subtree to scp-did, but scp-protocol/scp-event-log/scp-runtime also consume clock+crypto.
3. §62 blast-radius "~640 Clock / 61 DID sites" are unreconciled pre-move estimates; actual
   scp_did::DID = 509 refs across 203 files (61 understates realized radius ~3-8x).
