---
name: adr057-t1-as-built-final
description: ADR-057 T1 (dissolve scp-primitives, extract scp-did) final as-built review at cc23e51f6 — honest/complete with two line-85 framing precision gaps
metadata:
  type: project
---

ADR-057 T1 final as-built review (branch refactor/dissolve-primitives-split-identity, HEAD cc23e51f6, range 86519aa6f..HEAD).

**Verdict: SOUND — the ADR is honest and complete as-built.** Every concrete structural claim tested is true of the tree.

Why: T1 was a crate-topology slice (dissolve scp-primitives → scp-clock/scp-crypto; extract wasm-safe scp-did as the one DID-model home) that GREW to also carry z-base-32 canonicality hardening. The growth is coherent and disclosed. The port of canonicality into `scp_did::extract_public_key_from_did` is *intrinsic* to the split: the split makes scp-did the sole wasm-reachable did:dht parser (scp-event-log tree.rs + scp-protocol bridge/claiming.rs both call it; native hardened parser unreachable from wasm), so shipping it weaker would let the browser verify event-log sigs / claim attestations against keys native rejects. Hardening it = making the split safe, not scope creep.

Verified true of the tree:
- scp-primitives fully dissolved (only historical README/gate-comment refs remain); workspace has scp-clock (zero-dep), scp-crypto (ed25519-dalek only), scp-did (ed25519-dalek + serialization, NO scp-* edge, pure leaf).
- DID model has ONE home: scp-protocol no longer hosts DidDocument/VerificationMethod/decode_multibase_key/DID; scp-identity does not re-export it (no shim). IdentityLinkAttestation stays in scp-protocol — ADR line 101 discloses this residue honestly.
- 16 publishable crates (release.yml:863); scp-client-wasm correctly publish=false + excluded; leaves published first (clock/crypto/did).
- No-shim gate check-no-shim-reexports.sh added, crate set {scp_clock,scp_crypto,scp_did,scp_mls} = ADR line 126; scp-runtime/src/crypto/mls/mod.rs `pub use scp_mls` shim DELETED. scp_dht correctly absent from gate+workspace (T1c not landed).
- wasm fence = ci.yml:338 `cargo check -p scp-clock..scp-client-wasm --target wasm32-unknown-unknown`.
- 4 canonicality sites all present: scp_did::extract_public_key_from_did (port, re-encode+compare), scp_ffi_common::BridgeDidResolver→scp_did parser, app_sandbox→scp_did parser, DidDht::verify→same-file scp_identity::dht::extract_public_key (its own hardened parser). Only two ACTUAL zbase32::decode sites exist (scp-did lib.rs:123, scp-identity dht.rs:2732), both hardened; other did:dht refs are format-checks or encode-and-compare (verify_migration/self_certification), correctly outside the decoder set. Uniform-canonicality claim HOLDS.
- app_sandbox prefix bug REAL: pre-change (86519aa6f:903) `strip_prefix("did:dht:")` left the multibase 'z' → 33 bytes → rejected EVERY valid did:dht. Was a dead always-fail path.

Two precision findings (both QUESTION, corrected downstream — not false premises):
1. Line 85 says the three delegations go "onto the same guard by delegating to the single hardened parser" — but DidDht::verify delegates to a SECOND parser (scp_identity::dht::extract_public_key), so the tree has TWO z-base-32 authorities at end of T1, not one. Line 86 corrects this and defers single-authority consolidation to T1c ("collapse onto that one parser when the crate topology allows"). Line-85 "single hardened parser" overstates achieved uniformity.
2. Line 85 folds app_sandbox's prefix fix inside "All of these are fail-closed strictness only (they reject strictly more...)". The prefix fix is fail-OPEN functional repair (reject-all → accept-valid = strictly MORE accepted), opposite direction from strictness. Disclosed ("additionally fixes a prefix bug that rejected every valid did:dht DID") but mis-subsumed under the strictness banner. Underlying code correct (delegates to hardened parser + ed25519 verify).

Slice-identity drift (dimension d): T1 broadened from "behavior-preserving topology split" to "+ 4-site canonicality unification + one fail-open functional repair." Port-in-T1 is split-necessitated (sound). The three native delegations + app_sandbox repair are opportunistic (native decoders were unaffected by the topology move) but same-root-cause (z-base-32 non-injectivity), fully disclosed, correct. Bundling defensible; the WHY is honest, just implicit for the native sites.
