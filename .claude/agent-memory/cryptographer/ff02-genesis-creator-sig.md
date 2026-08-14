---
name: ff02-genesis-creator-sig
description: 0xFF02 group_context extension commits creator_did as UNSIGNED string; embedding a creator #active-key sig (#2027 GenesisAttestation) is feasible + strictly better than a separate artifact
metadata:
  type: project
---

# 0xFF02 creator binding vs GenesisAttestation (#2027)

Analyzed at origin/main HEAD 6d3ad0d1c (2026-08).

**Core structural fact:** the MLS leaf is signed by a FRESH `SignatureKeyPair::new()`
(scp-mls/src/group.rs:548), NOT the creator's DID `#active` key. So the `0xFF02`
`ScpContextExtension.creator_did` field is an UNAUTHENTICATED committed string — no
signature by creator_did's DID key exists in group state. Its authenticity for a
bundle-joiner comes ONLY from (bundle sig by #active, spec §5.12.3.1 step 1) ∧
(rule 8 cross-check bundle.creator_did == committed creator_did, spec §5.13.3:1733).

**Gap:** a joiner without a creator-signed bundle (late/governed/keyless/import-restore)
gets creator_did as an unsigned string — no #active sig in group state to verify → cannot
cryptographically confirm creator authored genesis. This is what #2027 GenesisAttestation
targets.

**Verdict: EMBED-IS-STRICTLY-BETTER.** Embed creator #active-key sig over
(domain || context_id || creator_did || genesis_params_hash || gov/ceiling/lineage hashes)
INTO 0xFF02. Must cover `genesis_params_hash = SHA-256(JCS(full ContextParams))` so it
subsumes the bundle's full-params authentication (not just the subset 0xFF02 commits today).

Feasibility all confirmed:
- 0xFF02 = `Extension::Unknown(0xFF02, UnknownExtension(Vec<u8>))`, JCS-JSON, already
  carries two [u8;32] hashes + DID; +64 sig +32 hash trivial (MLS ext data u16-len, max 65535).
- Immutable across epochs: tests context_extension_survives_welcome_join /
  _survives_later_commits (scp-mls/src/context_extension.rs). GroupContext folded into key
  schedule + confirmation_tag.
- Creator holds #active at genesis (already used for bundle sig); full ContextParams known
  at creation (input to for_root/for_child). NO circular dep: sig covers params, not the
  serialized-extension-with-sig nor group_id.

No hard constraint forces a separate artifact (rules out option B):
- credential-vs-DID-key: leaf uses fresh key but BOTH designs sign with #active — no differentiator.
- privacy: 0xFF02 ALREADY exposes creator_did cleartext to all members; a sig by #active
  leaks nothing new.
- "size in every message" is moot: GroupContext is STATE, not retransmitted per app message;
  +96 bytes is one-time-per-Welcome + per-epoch-hash, negligible.

Embedding's real advantage = liveness: separate artifact must be delivered/obtained or joiner
fails closed; embedded sig is guaranteed present (group invalid without 0xFF02, rule 1).

Caveat (applies to rule 8 TODAY too, not new): SCP process_commit (ratchet.rs) delegates to
OpenMLS and does not explicitly reject a hostile GroupContextExtensions proposal swapping
0xFF02. Both rule-8 and any embedded-sig rely on 0xFF02 genesis-immutability. Enforcement is
SCP-client-side (OpenMLS treats 0xFF02 as opaque) — "structurally impossible" = "rejected
before authority is built," same class as all SCP validation, still stronger than a missing
deliverable.
