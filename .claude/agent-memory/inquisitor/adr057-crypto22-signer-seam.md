---
name: adr057-crypto22-signer-seam
description: ADR-057 CRYPTO-22 signer-seam amendment — the provider-shim is forced ONLY by the parent's in-leaf-TBS decision (imperfect 0xFF01 analogy); out-of-band attestation collapses it
metadata:
  type: project
---

The 2026-08-03 ADR-057 amendment ("CRYPTO-22 identity-key signer-threading seam") proposes a
custom `OpenMlsCrypto` provider shim overriding `derive_hpke_keypair` to inject pre-generated
HPKE keys, so the `0xFF03` KeyPackage attestation can be signed over the leaf's public keys
BEFORE openmls's single leaf self-sign.

**Verdict: the seam is NOT forced in the absolute sense claimed ("the ONLY no-fork way").**
It is forced only *conditional on* the parent 2026-08-01 amendment's decision that the
attestation lives IN the leaf as an `0xFF03` LeafNode extension (in the signed TBS).

**Root cause:** the parent justified in-leaf by "mirroring the existing `scp_wrapping_key`
(0xFF01) LeafNode extension." That analogy is disanalogous: 0xFF01 carries an
externally-generated key (available before the self-sign, no shim needed), whereas 0xFF03
must bind keys openmls generates INTERNALLY (leaf `encryption_key`, KeyPackage `init_key`).
That disanalogy IS the entire source of the shim's complexity.

**The missing alternative (absent from both amendments' rejected lists):** carry the
attestation OUT of the leaf TBS and sign it AFTER a normal openmls build, reading the four
public keys via openmls public getters — `LeafNode::encryption_key()` (leaf_node.rs:394),
`::signature_key()` (:399), `KeyPackage::hpke_init_key()` (mod.rs:418), wrapping_key already
in hand. This eliminates Decision 1 (shim), Decision 2 (pre-generation), and the
private-HPKE-key-across-mailbox half of Decision 4, plus risk-1 (openmls draw-order coupling).
No binding security is lost: the attestation's own `#active`/`#agent` signature provides the
DID↔keys binding; the leaf self-sig by the (attested) ephemeral signature_key transitively
covers the rest. In-leaf buys only delivery/tree-convergence convenience, NOT a crypto
binding property — and that tradeoff was never surfaced.

**Facts confirmed on openmls 0.8.1 (pinned) + origin/main:**
- Force 2 mechanism is real: both `init_key` and leaf `encryption_key` route through
  `crypto.derive_hpke_keypair` (`EncryptionKeyPair::random` → `derive_hpke_keypair`); LeafNode
  payload private, all sign paths `pub(crate)`, no public re-sign, no key-injection builder.
  So GIVEN in-leaf, the shim is indeed the only no-fork route. That part is sound.
- Force 1: `KeyCustody::sign` IS RPITIT (`crates/scp-platform/src/traits.rs`, `sign` at :344),
  so `Arc<dyn KeyCustody>` genuinely does not compile. But "sign MUST happen outside the actor"
  is slightly overstated — an object-safe erasure wrapper (`Pin<Box<dyn Future>>`, blanket-impl
  for `C: KeyCustody`) exists. Conclusion still defensible on independent grounds (per-operation
  caller-supplied custody; don't hand the actor a durable signing handle). QUESTION, not blocker.

The amendment is internally sound given its parent premise; the challenge is to the parent's
unexamined in-leaf-TBS premise. Fix flows down: re-open the parent 2026-08-01 amendment's
in-leaf decision and weigh out-of-band before wiring S3's shim.
