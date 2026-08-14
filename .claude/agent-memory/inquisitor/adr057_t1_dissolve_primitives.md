---
name: adr057-t1-dissolve-primitives
description: ADR-057 T1 topology split (dissolve scp-primitives → scp-clock/scp-crypto/scp-did) review — sound refactor, but ADR text drifted from what was built
metadata:
  type: project
---

ADR-057 Amendment T1 (commit d12691ef6, branch refactor/dissolve-primitives-split-identity)
dissolved `scp-primitives` into capability crates. The refactor itself is SOUND (behavior-preserving
module moves; scp-did is a coherent DID-data-model crate; DHT-not-separable claim holds; no stale
refs; consumers import scp_did directly, no latent indirection).

**Why (the ADR's driving principle):** "a crate named for a generality tier has no refusal criterion —
anything low-level enough accretes." Split into capability crates that can say *no*.

**Findings worth recalling (ADR text vs as-built drift — fix flows to the ADR, not code):**
- ADR §Amendment table (line 104) claims `scp-clock` owns "the hardened wasm Date.now clock, Prereq 1."
  As-built: scp-clock is a **zero-dep pure leaf**; the hardened clock lives in
  `scp-client-wasm/src/time.rs` (needs wasm-bindgen/js-sys — correctly kept OUT of the leaf). ADR is wrong, code is right.
- ADR mechanical rule "No re-exports, no back-compat shims. Every consumer imports the real crate" is
  **overbroad as worded** — `scp-core` is a sanctioned re-export facade that survived AND grew a new
  merged `crypto::mls` re-export (scp_mls + scp_runtime bridge). Real intent = "no *shim* re-exports of
  the dissolved types." scp-core facades scp-mls but NOT scp-did/scp-clock/scp-crypto (mild facade asymmetry).
- rejected-alt-5 (DHT not separable) is directionally correct but imprecise: `dht_client/` transport is
  coupled only via `IdentityError` (weaker than dht.rs's DidDht↔ScpIdentity↔MigrationPartialState embedding).
  Still un-extractable without moving IdentityError (→cycle), so conclusion holds.

**Drift/consistency (premise e):** `scp-platform` (KeyCustody + Storage + DeviceAttestation + KDF +
pseudonym) is the live counterexample the ADR's universal naming-principle would interrogate but doesn't
address. Weaker smell than primitives (shares axis "varies with host platform") but KDF/pseudonym are
pure crypto strays. If the principle is universal, ADR should say why scp-platform/scp-protocol survive
or it reads as special pleading. [[operating-reminders: apply principle consistently or it's special pleading]]

**Identity-link attestation split is COHERENT (not a stray):** scp-did owns `IdentityLinkServiceEntry`/
`IdentityLinkPlatform` (used by DidDocument's own service-entry methods) — DID-document-embedded types;
scp-protocol keeps standalone `IdentityLinkAttestation` wire message. Principled line = "appears inside a
DID document" → scp-did.
