---
name: adr057-t1-dissolve-primitives
description: ADR-057 Amendment T1 (dissolve scp-primitives, extract scp-did) as-built review — verdict + the one live coherence contradiction
metadata:
  type: project
---

Reviewed branch `refactor/dissolve-primitives-split-identity` (HEAD b85daa755, range 86519aa6f..HEAD) against the ADR-057 Amendment as-built.

**Verdict: SOUND on the load-bearing decisions; one MEDIUM artifact-coherence defect.**

What held (re-derived from current tree, not the ADR's assertions):
- scp-primitives fully dissolved into scp-clock (zero-dep leaf) / scp-crypto (ed25519 only) / scp-did (DID model). Manifests match the crate table. No lingering `scp_primitives` refs except historical READMEs + gate comment.
- scp-protocol strays (`identity/document.rs`, `identity/did_attestation.rs`) moved into scp-did (`document.rs`, `attestation.rs`); scp-protocol → scp-did edge is correct direction.
- T1c bep44 consumer inventory is EXACTLY the 6 sites the ADR lists, and the production(2)/test(4) split is accurate (verified via nearest test-marker). Helper signatures match the coupling claim: `bep44_signable(&[u8],u64)->Vec<u8>` (no identity types), `verify_bep44_signature(...)->Result<(),IdentityError>` (sole coupling = error channel, what DhtError replaces).
- Enforcement map all 4 mechanisms present + wired: acyclicity (rustc), wasm fence (ci.yml:337-338 builds scp-clock/crypto/did/protocol/mls/client-wasm for wasm32), banned-deps (check-protocol-deps.sh), no-shim gate (check-no-shim-reexports.sh, ci.yml:187 — recursive `find crates -type d -name src`, closed set of 4 crates, honestly scoped to canonical spellings).
- mls/mod.rs `pub use scp_mls::*` shim deleted; scp-runtime imports from scp_mls directly.

**The live finding (MEDIUM, artifact only):** ADR line 41 parenthetical "(The DHT was *not* split into a separate crate — the type graph rejects that seam; see the Amendment's rejected alternative 5.)" is a stale orphan from before T1c was carved out. It directly contradicts T1c (lines 86,137) and rejected-alt-5-as-amended (line 135: "Rejected **at the DID-method layer**, approved **at the transport layer**") which approve extracting the DHT *transport* into scp-dht. Fix the artifact (qualify line 41 to "the DID-method layer was not split").

**Minor (LOW):** scp-protocol/src/identity/ still holds identity-adjacent types (esp. `IdentityLinkAttestation` §3.5, now importing scp_did::DID). By rejected-alt-1's own logic ("identity domain types in scp-protocol = junk-drawer-class smell") this is the same tension the Amendment flagged honestly for scp-platform/kdf — but left unflagged here. Defensible to keep them (protocol wire types), but the silence breaks the Amendment's stated honesty standard. Also: scp-did's real dep set (serde/hex/base64/bs58/z-base-32/thiserror) is broader than the ADR's "deps = scp-crypto + ed25519-dalek" characterization (benign serialization deps).
