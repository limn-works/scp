---
name: adr057-t1-primitives-dissolution
description: ADR-057 T1 scp-primitives dissolution / scp-did extraction review — two premise gaps (dht coupling undercounted; "enforced" overstated)
metadata:
  type: project
---

ADR-057 Amendment T1 (branch refactor/dissolve-primitives-split-identity, HEAD 8d6819674):
dissolve scp-primitives → scp-clock/scp-crypto/scp-did; keep scp-identity's native
DHT/DidMethod subsystem whole; planned T1c extracts only dht_client/ as scp-dht.

**Why (findings that recur):**
- **Coupling-surface claims must be checked against call sites, not just type signatures.**
  ADR rejected-alt-5 + T1c claim "dht_client's ONLY coupling to scp-identity is IdentityError
  in the two DhtClient method signatures." FALSE: `crates/scp-identity/src/dht_client/pkarr_client.rs:181`
  calls `crate::dht::verify_bep44_signature` — a fn in dht.rs (the DID-method layer the ADR says
  STAYS in scp-identity). That's a second edge; naive T1c (just add DhtError) → scp-dht→scp-identity
  back-edge = crate cycle rustc rejects. Fix = also move verify_bep44_signature + bep44_signable
  into scp-dht (BEP44 = transport concern), have dht.rs/resolution.rs/resolver.rs import them back.
  This ADR text was ADDED in commit 8d6819674 (F) AFTER an 8-reviewer audit — the audit missed it.
- **"Mechanically enforced, not prose-policed" is a claim to verify against an actual gate.**
  ADR mechanical rule #1 (no back-compat shim re-exports of moved types, anywhere) has NO gate.
  Proof: commit 1 (d12691ef6) shipped `pub use scp_clock::{...}` shims (scp-event-log/src/time.rs,
  scp-identity/src/cache.rs); passed CI; only removed in commit 3 after manual audit. A real gate
  would have failed commit 1. Rules #2 (acyclicity = rustc-inherent) and #3 (fence = wasm32 CI
  compile-check at ci.yml:336 covering scp-clock/crypto/did/protocol/mls/client-wasm) ARE genuinely
  enforced — so the blanket "all enforced" is wrong only for #1.

**How to apply:** When an ADR asserts a crate's coupling surface or that a rule is "enforced,"
grep the actual call sites (`crate::`/`super::` into the sibling) and grep scripts/ for the actual
gate. Undercounted coupling + overstated enforcement are the two phantom-provenance failure modes
in topology-split ADRs. Latent (pre-existing, not introduced): two did:dht:z parsers drift-risk
(scp-did::extract_public_key_from_did vs scp-identity::dht::extract_public_key).

SOUND parts: scp-did contents are all DID data model (no strays); DID model genuinely left
scp-protocol (protocol keeps identity/ = wire types like IdentityLinkAttestation §3.5.1 importing
scp_did::DID — principled data-model-vs-message split, not special pleading); scp-clock zero-dep
leaf; WasmClock correctly in scp-client-wasm; release.yml publish order valid topological sort.
