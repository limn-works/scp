---
name: crypto22-signer-seam-adr057-amendment
description: CRYPTO-22 ADR-057 amendment (2026-08-03) mechanizing the identity-key signer-threading seam for slices S3/S5 — reviewed APPROVED
metadata:
  type: project
---

ADR-057 amendment "CRYPTO-22 identity-key signer-threading seam" (branch `adr-057-signer-seam`, docs-only +76 lines) reviewed 2026-08-03 → architecturally sound, APPROVED to govern code slices S3/S5.

**What it settles:** how the DID identity signature reaches into openmls's single leaf self-sign (RFC 9420 §5.3 TBS includes the `0xFF03` LeafNode extension, so attestation must be in the leaf extension set BEFORE openmls's one self-sign; no re-sign path in openmls 0.8.1).

**Five decisions (mostly forced by two forces):**
- Force 1: `KeyCustody` is RPITIT (`crates/scp-platform/src/traits.rs:324`, sign at :344) → not dyn-safe → `Arc<dyn KeyCustody>` can't exist → sign OUTSIDE the actor, only signature crosses mailbox. Reuses `dispatch_broadcast_command_with_custody<C>` (supervisor.rs:5858, "custody never crosses the mailbox") + `KeyCustodySigner<'a,C>` — established ADR-049 precedent, NOT a new pattern.
- Force 2: openmls 0.8.1 gives no HPKE key injection + no leaf re-sign (LeafNode private, sign paths pub(crate)); only no-fork seam = the provider abstraction. Wrap `RustCrypto`'s `derive_hpke_keypair` to return pre-generated keypairs (`ScpMlsProvider` sets CryptoProvider=RandProvider=RustCrypto, storage.rs:977/1007).
- (1) custom OpenMlsCrypto/Rand wrapper injecting HPKE keys; (2) pre-generate leaf sig key + 2 openmls HPKE keys at custody boundary; (3) one-shot `KeyCustody::sign<C>`; (4) carry keys+0xFF03 across mailbox into in-actor build; (5) NEW async document-returning resolver seam ALONGSIDE sync `KeyResolver` (governance/mod.rs:88, bare VerifyingKey, discards freshness) — needs `DidResolutionResult{document,staleness}` (cache.rs:58) for MAX_ATTESTATION_KEY_RESOLUTION_STALENESS (§9.18.7, 300s). Async avoids the block_in_place `colocated_document_vm_key_resolver` (self_host.rs:506) forces on actor task.

**Three leaf-build sites S3/S5 must rework:** create_group (scp-mls group.rs:411), KeyPackage mint (`key_package_actor.rs:785` hardcoded `SigningKeyId::Active` — S5 deletes; actual path is context/**supervisor**/key_package_actor.rs), epoch advance/self_update (production_backend advance_epoch:444, state.rs:2501) = largest lift, draw-order risk bites hardest.

**Persona:** thread `signing_key_id` field (default #active) via same seam as MessageSigner/MintParams (ucan/mint.rs:368/411); does NOT build the persona *determiner* (parked → RFC #2242, no agent-initiated-join caller exists on origin/main = real external constraint, not scope-cut).

**Citations verified against origin/main 093c5afca:** all spot-checked sites (KeyCustody, dispatch_custody, ScpMlsProvider, KeyResolver, DidCache Staleness/DidResolutionResult, colocated resolver, create_group, MintParams, key_package_actor:785, provider.rs:615) accurate.

**Non-blocking nits flagged:** (1) scope-qualifier "the only non-test SigningKeyId::Active construction sites" is imprecise — many non-test Active sites exist; true claim = only non-test *ScpCredential* Active mint sites (785 + provider.rs:615); (2) Decision-1 wrapper: only `derive_hpke_keypair` needs override — OpenMlsRand + real Storage must be pass-through (coder could lose real context storage if they wrap in-memory everything); (3) risk register could add two-resolver source-coherence line.

**Why:** documents an APPROVED architectural seam future S3/S5 reviews will build on.
**How to apply:** when reviewing CRYPTO-22 S3 (provider shim / leaf-build rework) or S5 (persona threading / hardcode removal), hold the code to these 5 decisions + the draw-order test gate (assert built leaf HPKE pubkeys == pre-generated); watch the storage-preservation nit.
