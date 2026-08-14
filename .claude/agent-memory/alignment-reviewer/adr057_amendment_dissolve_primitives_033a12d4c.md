---
name: adr057-amendment-dissolve-primitives-033a12d4c
description: ADR-057 Amendment (dissolve scp-primitives → scp-clock/scp-crypto/scp-did; DidDocumentError→DidError) review at 033a12d4c — 1 MODERATE finding (dead scp-protocol dep in scp-identity)
metadata:
  type: project
---

# ADR-057 Amendment "Dissolve scp-primitives; split scp-identity" @ 033a12d4c (2026-07-02) — NEEDS DISCUSSION (1 MODERATE)

Branch `refactor/dissolve-primitives-split-identity`, range `86519aa6f..033a12d4c` (367 files, +2706/-2439). Behavior-preserving topology split.

**Why:** ADR-057 in-browser client needs DID model wasm-reachable; interim Slice-1a parked it in scp-protocol + scp-primitives w/ re-export shim (all forbidden). Amendment dissolves scp-primitives → scp-clock (Clock/SystemClock/TestClock/ClockError, zero-dep leaf) + scp-crypto (verify_ed25519_signature) + scp-did (DID/SigningKeyId/DidDocument/proofs/attestation, DidDocumentError→DidError, wasm-safe, deps=scp-crypto+ed25519-dalek). scp-identity keeps native DHT/DidMethod, imports model from scp-did. scp-dht NOT created (T1c is a forward-only follow-up; correctly absent).

**How to apply:** VERIFIED matching ADR exactly — crate table, dep graph (scp-protocol/scp-event-log→scp-clock+scp-crypto+scp-did; scp-mls→scp-did+scp-protocol; scp-client-wasm fence holds: no scp-runtime/scp-identity/tokio), enforcement map (rustc acyclicity + wasm32 CI job now covers scp-clock/crypto/did/protocol/mls/client-wasm + new scripts/check-no-shim-reexports.sh — closed allowlist of 4 crates, scp-core facade exempt, wired in ci.yml:187 & passes), mls/mod.rs `pub use scp_mls` shim DELETED, T1c coupling inventory ground-truth accurate (pkarr_client.rs:181 calls crate::dht::verify_bep44_signature; bep44 helpers in dht.rs; two extract parsers exist). architecture.md + CLAUDE.md + release.yml + fuzz retargeted correctly.

**FINDING (MODERATE, code↔artifact divergence):** `crates/scp-identity/Cargo.toml:16-20` — `scp-protocol` dep is now provably UNUSED (`extern crate scp_protocol is unused in crate scp_identity`; 0 `scp_protocol` tokens in src/tests) and its comment still describes the SUPERSEDED Slice-1a topology ("DID-document…types moved here…scp-identity re-exports them") — both clauses false post-amendment (types moved OUT to scp-did; re-export deleted). The amendment's own thesis is "delete every shim / no dumping grounds / imports instead of re-exporting" — this dead edge+comment is exactly the residue it set out to remove. FIX: drop the scp-protocol dep + stale comment. Non-behavioral, CI won't catch (unused_crate_dependencies lint not enabled).

Observations (non-findings): ClockError is `pub(crate)` though table lists scp-clock as "owning" it (owns=hosts, fine); architecture.md dropped historical issue refs (#93/#94/#233/#1446) in the rewrite (docs, fine).
