---
name: crypto22-four-key-binding-verdict
description: Why the CRYPTO-22 KeyPackageAttestation MUST bind all four leaf public keys (not just signature_key) — the refutation, the RFC 9420 facts, and what it implies for the ADR-057 provider shim.
metadata:
  type: project
---

# CRYPTO-22: four-key attestation binding is NOT redundant (verdict 2026-08-10)

**Question asked:** could `KeyPackageAttestation` (§9.5.2) bind only `leaf_signature_key`,
relying on RFC 9420's LeafNode self-signature to transitively cover `encryption_key`,
`0xFF01 wrapping_key` (LeafNodeTBS) and `init_key` (KeyPackageTBS)?

**Verdict: REFUTED for all three HPKE keys.** All four bindings are load-bearing.

**Why:** the transitive chain is real but rooted in the *ephemeral leaf signature key*,
not the DID. RFC 9420 §16.5 (rfc9420.txt:5506) names exactly this threat: "If a member's
signature key is compromised, then an attacker can create LeafNodes and KeyPackages
impersonating the member." SCP spec §9.12 names the same case ("Leaf-key / MLS-state
compromise (ephemeral leaf key leaked, identity keys intact)") as a first-class recovery
scenario, and says separating the leaf key from identity keys "is the entire point of the
attestation model."

Concrete attack under a 1-key attestation: thief with only `sk_leaf` mints a fresh
KeyPackage carrying the victim's `signature_key` + the victim's genuine copied attestation
+ **attacker-chosen** `init_key`/`encryption_key`/`wrapping_key`, self-signs LeafNodeTBS and
KeyPackageTBS with `sk_leaf`. Every remaining check passes → Welcome seals to the attacker
→ full read-as-victim in any group. 4-key binding turns the attestation from a *minting
capability* (valid up to `MAX_KEYPACKAGE_ATTESTATION_LIFETIME` = 84d, context-agnostic) into
a *one-shot commitment to one specific leaf*.

## Decisive code fact (origin/main)

SCP's `self_update` **keeps the old `signature_key`** and regenerates `encryption_key`
every epoch: `crates/scp-mls/src/ratchet.rs:132` and `:183` pass `LeafNodeParameters` with
no `credential_with_key`; openmls writes `signature_key` only in the
`credential_with_key.is_some()` branch (`leaf_node.rs:344-390`);
`self_update_with_new_signer` has **zero** SCP call sites.
⇒ under a 1-key attestation, ONE attestation minted at join would stay valid for the leaf's
whole life while the real decryption key rotates underneath it every epoch, and `#active`
rotation (§9.12 revocation lever) would revoke nothing for admitted members.

## RFC 9420 ground truth (verified verbatim)

- LeafNodeTBS covers `encryption_key`, `signature_key`, credential, capabilities,
  leaf_node_source, Lifetime|parent_hash, `extensions` (so `0xFF01` + `0xFF03`), plus
  `group_id`+`leaf_index` **only** for `update`/`commit` sources — a `key_package`-source
  leaf is bound to NO group (that's the cross-group transplant surface, §9.7.3).
- KeyPackageTBS (§10, rfc9420.txt:3493) covers `init_key`; signed by the SAME `signature_key`.
- §10.1 requires verifying the KP signature and `init_key != encryption_key` (rfc9420.txt:3545-3549).
- `Lifetime` exists ONLY for `leaf_node_source == key_package`. openmls builds the creator
  leaf as `LeafNodeSource::KeyPackage(life_time)` (`treesync/mod.rs:397`) so it HAS one; an
  Update leaf (`LeafNodeSource::Update`) and Commit leaf (`Commit(parent_hash)`) do NOT.

## Open spec defect found

§9.7.1 **check 11** (`issued_at`/`expires_at` == leaf `Lifetime.not_before`/`not_after`) is
listed as applying on **both** triggers, but an Update/Commit-source LeafNode has no
`Lifetime`. The implemented verifier requires it unconditionally:
`crates/scp-mls/src/keypackage_attestation.rs` `AttestationLeafGroundTruth.leaf_lifetime_not_before/_not_after`
(~:683-687) with `trigger: AttestationTrigger::Update`. Any Update-path caller must invent
those values ⇒ reconstructed-from-args placeholder hazard. Fix the spec first.

Also: §23.10 still describes a **one-key** binding ("binding the leaf's ephemeral MLS
signature key to the member's DID") — stale vs the merged §9.5.2 four-key model.

## Implementation state (origin/main 8b7cbe7f8)

- `crates/scp-mls/src/keypackage_attestation.rs` (~2036 lines) EXISTS: 0xFF03 const,
  domain sep, `signing_hash`, `to_extension_body`/`from_extension_body`,
  `verify_attestation` (checks 3–13), `verify_attestation_with_resolution` (checks 1–2),
  KAT Vector 37 tests.
- `crates/scp-runtime/src/crypto/mls/attestation_verification.rs::verify_add_attestation` exists,
  **zero callers**.
- **NO mint function, ZERO production wiring.** No 0xFF03 attached in `group.rs` /
  `ratchet.rs` / `key_package_actor.rs`. S5/S6/S7 unbuilt.

## ADR-057 signer-seam amendment (branch adr-057-signer-seam, c1bfbd19a, Proposed) — corrections

The shim is still needed (obligation stands), but the amendment has three defects:

1. **Decision 1's "order-independent" is FALSE**; risk 1 is right. On `self_update`,
   `apply_own_update_path` (`treesync/diff.rs:315`) derives the whole direct path FIRST
   (`messages/mod.rs:373`, once per filtered-direct-path node — varies with tree size, leaf
   index, blanks) and the **leaf** key LAST (`leaf_node.rs:276`). A call-counting shim
   cannot know the leaf's call index without replicating `filtered_direct_path`.
2. **Factual error**: the amendment lists 5 non-test `derive_hpke_keypair` sites incl.
   `extensions/external_pub_extension.rs:64` — that one is inside a `#[cfg(test)] mod`
   (gate at `:40`). There are **4** non-test sites: `schedule/mod.rs:816`,
   `messages/mod.rs:373`, `treesync/node/encryption_keys.rs:216`, `key_packages/mod.rs:301`.
3. **Risk-1 mitigation is a test, must be a production fail-closed post-condition.**

**Robust discriminator the amendment missed:** the 4 sites differ in ikm *provenance* —
`encryption_keys.rs:216` and `key_packages/mod.rs:301` draw ikm from `Secret::random(rand)`;
`messages/mod.rs:373` and `schedule/mod.rs:816` use KDF output and never touch the RNG.
So wrap `OpenMlsRand` to hand out fresh-random recorded **sentinel** ikms and have
`derive_hpke_keypair` match on ikm **value** (not call index), delegating otherwise. That is
topology-independent. Plus: after the build, read back
`key_package.leaf_node().encryption_key()`, `.hpke_init_key()`, the `0xFF01` ext and
`signature_key` and hard-fail + zeroize on any mismatch with the attested values.

**Cost to accept honestly:** every epoch advance needs an async `KeyCustody::sign` on the
commit path (§9.7.1 Update trigger + check 5/6).

Related: [[key-files-index]], [[scp1717-prerotation-custody]], [[adr039-persona-binding-and-signatures]]
