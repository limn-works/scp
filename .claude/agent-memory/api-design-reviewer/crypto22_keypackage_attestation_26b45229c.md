---
name: crypto22-keypackage-attestation-26b45229c
description: CRYPTO-22 spec-only review — KeyPackageAttestation (0xFF03 LeafNode ext) replacing leaf==DID rule; re-review @20f7a036b APPROVED (all blockers resolved)
metadata:
  type: project
---

**RE-REVIEW @20f7a036b (2nd pass): APPROVED — CLEAN.** All prior blockers RESOLVED, verified byte-exact. Structure changed since 26b45229c: preimage is now **5 fields (context_id DROPPED — attestation is context-agnostic**, group-scope carried redundantly by 0xFF02; rationale = KeyPackage mintable offline before group known). Homes moved to §9.5.2 (5-field table), §9.7.1 (6-point verify MUST-list), §25.22/Vector 37, constants row §9.18 (line 1798).
- MAJOR-1 (wire-format) RESOLVED: §9.5 line 457 defines 0xFF03 body as "deterministic length-prefixed binary — explicitly NOT MessagePack/JCS": BE32-len UTF-8 for did+signing_key_id, raw-32 leaf_signature_key, BE64 timestamps, trailing raw-64 sig; domain sep excluded from body (called out 2×); mirrors 0xFF01 style. Zero divergence surface.
- MAJOR-2 (vector) RESOLVED: §25.22 Vector 37 byte-exact. I reproduced it: preimage 115B hex exact, SHA-256=ac56e3df…3730 exact, pubkey derives from §25.2 seed, Ed25519 sig over the 32B hash matches vector exactly (cryptography lib). Pins both preimage AND ext body.
- MOD-1/2/3 RESOLVED into single MUSTs: verify rule#4 = explicit signing_key_id credential==attestation equality; rule#5 = expires_at==Lifetime.not_after AND issued_at==not_before (equality, not advisory); rule#6 = issued_at<expires_at + unexpired + future-skew≤§9.14 5min.
- Producer single-path: minted at all 3 leaf-creation sites (create_group/add-time-KP/PCS-Update), creator-leaf edge (Lifetime, no KeyPackage.Lifetime) handled so rule#5 has no hole. Fail-closed, testing carve-out gated behind `testing` feature. context_id removal adds NO replay surface (leaf reuse needs private leaf sig key; 0xFF02 binds group).
- Residual polish only (non-blocking): verify intro says "the leaf's signing_key_id" w/o naming credential-vs-attestation copy (moot — rule#4 enforces equality); §9.18.7 xref points at "MLS and UCAN" constants nbhd not a dedicated ext-definition heading.

---
(original 1st-pass review @26b45229c below — superseded)

CRYPTO-22 / #2187, branch `crypto-22-attestation-spec` @26b45229c (ADR-057 amendment). Spec-only. Replaces the "MLS leaf signature_key IS the DID #active/#agent key" rule with an explicit **KeyPackageAttestation**: a #active/#agent-signed statement binding the ephemeral context-scoped MLS leaf key to the DID, carried as LeafNode extension `scp_keypackage_attestation` type `0xFF03`, domain sep `"SCP-KEYPACKAGE-ATTESTATION-V1:"`. Spec homes: §9.5.2 (6-field preimage: context_id/did/leaf_signature_key/signing_key_id/issued_at/expires_at), §9.7.1 (verify MUST + rotation), §9.18.6 (ext type), §9.18.2 (domain sep). Analog claimed to IdentityLinkAttestation §3.5.2. ScpCredential is a real type in scp-mls (has .did + .signing_key_id).

**Verdict: NEEDS REVISION.** Design is sound (fail-closed, #0 excluded, bounded did:test:/did:key: carve-out, KeyCustody::sign no-raw-export) but surface NOT cross-target-unambiguous.

MAJOR-1: extension PAYLOAD wire serialization undefined — §9.5.2 pins only the signature PREIMAGE (canonical hash). The bytes stored in the 0xFF03 extension (6 fields + 64-byte Ed25519 sig, parsed by verifier) have no named encoding. Peers DO name theirs: 0xFF01 scp_wrapping_key = raw 32-byte X25519; 0xFF02 scp_context_params = "JCS-serialized". "Direct analog of IdentityLinkAttestation" is drawn for TRUST MODEL not bytes (and ILA uses named-key sorted MessagePack §3.5.2 — different discipline). Ext covered by leaf self-sig ⇒ byte-layout disagreement = total interop failure across native/wasm/uniffi/napi.
MAJOR-2: no §25 test vector. All peer signed-structs have byte-exact vectors (25-test-vectors.md, 49 refs; ILA cites Vector 26/29). New struct = 0. Repo enforces "same preimage bytes" mechanically via §25.
MODERATE-1: two signing_key_id copies (preimage field 4 vs credential.signing_key_id) — verifier resolves VM from credential copy; no stated equality check. Fails-closed under attack but implementations diverge on accept-set (A cross-checks+rejects, B ignores field4).
MODERATE-2: expires_at "matches Lifetime.not_after" (field 6) but MUST-list only checks "unexpired" — MUST-equal vs advisory unstated.
MODERATE-3: issued_at in preimage but zero verifier semantics (no not-before/freshness) — implementations invent divergent windows.
LOW: name "KeyPackage*" undersells that it re-issues on every Update/leaf-key rotation + re-verifies on Commit/Proposal (really LeafKeyAttestation); field-3 name drift leaf_signature_key (table) vs signature_key (prose). Downstream refs (§05:2186 bound-creator, §10:441 per-device, §23:193, ADR-057, phase-1.md) consistent, no stale leaf==DID residue.
