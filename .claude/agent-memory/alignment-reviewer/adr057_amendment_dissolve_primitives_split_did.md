---
name: adr057-amendment-dissolve-primitives-split-did
description: ADR-057 Amendment T1 review (dissolve scp-primitives → scp-clock/scp-crypto/scp-did) @ 81ef76c56 — ALIGNED, 0 findings
metadata:
  type: project
---

# ADR-057 Amendment T1 (dissolve scp-primitives; extract scp-did) @ 81ef76c56 — ALIGNED, 0 divergences

Branch `refactor/dissolve-primitives-split-identity`, range `86519aa6f..81ef76c56` (7 commits, +2730/-2427, 371 files). Mostly mechanical import retarget over the whole tree + ADR amendment.

**Why:** ADR-057 Prereq-3 interim parked DID types in scp-protocol + scp-primitives with a re-export shim — the smell it was meant to fix. Amendment dissolves scp-primitives into 3 wasm-safe capability leaves.

**How to apply:** If re-reviewing later slices (T1c DHT-transport→scp-dht, T2 client storage), this is the landed T1 baseline. All verified clean:
- Crate table (ADR §105-110) matches code exactly: scp-clock (zero-dep leaf), scp-crypto (ed25519-dalek only), scp-did (ed25519-dalek + serialization; NO scp-crypto edge; validates via `ed25519_dalek::VerifyingKey::from_bytes` at decode_multibase_key). `cargo tree -p scp-did` = pure leaf (no scp-* deps). DidDocumentError→DidError rename complete (0 lingering).
- scp-protocol strays removed: identity/document.rs + did_attestation.rs gone; IdentityLinkAttestation (§3.5.1 wire msg) correctly STAYS in scp-protocol/identity/attestation.rs importing scp_did::DID (no dup — scp-did/attestation.rs has the DID-doc service-entry types, not the wire message).
- Gate `scripts/check-no-shim-reexports.sh`: closed set {scp_clock,scp_crypto,scp_did,scp_mls}, scp-core facade exempt, wired into CI protocol-deps job, registered in CLAUDE.md enforcement list. Passes. mls/mod.rs `pub use scp_mls` shim deleted.
- Release order dependency-valid: clock,crypto,did,platform,event-log,protocol,identity,mls,client,client-wasm,runtime,... CI path filters + wasm-check job (clock/crypto/did/protocol/mls/client-wasm) + docs.yml updated.
- Standalone crates retargeted: fuzz, scaffolds/rust-client (DID+SigningKeyId from scp_did, DidMethod stays scp_identity), templates/cross-context-bridge (dropped scp-identity dep), templates/personal-relay (SystemClock from scp_clock). 0 lingering scp_primitives in code.
- architecture.md/specs 16,20,21/white-paper (6→11 crates, count correct) all coherent.

**Two low-severity observations (NOT findings, ADR-sanctioned):**
1. scp_did::extract_public_key_from_did LACKS the z-base-32 canonicality round-trip check that scp_identity::dht::extract_public_key (dht.rs:2751) HAS — weaker parser now on the wasm-safe path. ADR §86 T1c "Consolidation candidate" explicitly sequences porting the check into scp-did FIRST, then consolidating. Code matches ADR; mild tension with "no deferral" tenet but ADR governs the sequencing.
2. Amendment heading "split scp-identity" is a mild misnomer — body concludes scp-identity is NOT split (stays one native crate; DID model relocated from scp-primitives+scp-protocol, not carved out of identity in this change set). Editorial only; body is unambiguous.
