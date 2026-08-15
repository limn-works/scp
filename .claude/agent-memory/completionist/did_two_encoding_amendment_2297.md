---
name: did-two-encoding-amendment-2297
description: Review of the #2297 DID two-encoding amendment (78c72b6e7..7fa2d9258) — where the deleted one-document-two-layers rule survived, and the verification pass at 7fa2d9258
metadata:
  type: project
---

The #2297 amendment split the DID document into two encodings, one per resolution layer:
the SCP relay layer carries the full W3C JSON document (cap 262,039 = MAX_BLOB_SIZE − 105
frame prefix); Mainline DHT carries a four-element "bootstrap core" (`#0` by derivation,
`#active`, `PreRotationCommitment`, `SCPRelay` entries) as a did:dht DNS packet under
BEP44's 1,000-byte cap. It DELETED: cross-layer byte-identity, cross-layer
highest-sequence-wins, cross-layer healing, and "the DHT carries the full document."
Normative homes: `.docs/specs/03-identity.md` §3.10.4/§3.10.5/§3.10.7 and
`.docs/specs/18-addressability-and-deployment.md` §18.2.2A–D.

**Why:** the code published pretty-printed JSON to Mainline; BEP44 rejects it and the
`mainline` crate reports that rejection as a *timeout*, so the DHT namespace was silently
empty for every SCP identity. Issue #2297 is the root-cause filing.

**How to apply:** when a downstream artifact says "the other layer serves it," "highest
seq regardless of layer," or "publish the document to both layers," it is asserting a
deleted rule — the amendment's own §3.10.7/§18.2.2A wording is what governs.

## Verification pass at 7fa2d9258 — all 15 prior findings LANDED; 3 new classes found

The dominant survival pattern shifted. On the first pass the deleted rule survived in
files the amendment did not touch. On the second pass it survived **inside paragraphs the
amendment edited**:

- `03-identity.md` §3.10.8 suppression bullet: the amendment rewrote the *integrity*
  clause of that bullet to be per-layer and left the *leading claim sentence*
  byte-identical ("suppress the DID document on ALL of an identity's validating relays
  AND all reachable DHT nodes"). **Diff the paragraph, not the section — an edited
  paragraph is not a checked paragraph.**
- `17-persistence-and-storage.md` §17.17.3: a whole new paragraph
  ("The two-encoding model sharpens this harm") was appended while the bullet three lines
  above kept the un-split conjunction.

**A security classification amended in one place and asserted unconditionally in three
others is the highest-value class.** ADR-062 §Decision 5 + its line-41 table row were
re-argued to say `NoOpRelayQuerier` is a nullifier-by-effect until §3.10.10's two-variant
`ResolvedDidDocument` ships (it has not — `resolver.rs:69` is still a single struct). But
ADR-062 lines 16/140/172 still assert "not a nullifier, ships honestly" unconditionally,
two of them *citing §Decision 5* as authority, and the downstream PRD
`adr062-capability-injection.json` repeats the retired argument in six places — including
an **acceptance criterion** (`grep ... NO #[cfg(...)] gate precedes it`) that would
mechanically lock in the retired classification. When an amendment qualifies a
classification, grep the ADR for every other mention of the classified symbol AND every
downstream story field.

**Phantom provenance to hunt after any amendment:** `phase-1.md:779` says "the highest
valid `seq` is authoritative across the relay *and* the DHT — §3.10.7" and attributes to
§9.6.1 a quote §9.6.1 does not contain. Both cited sections now say the opposite.

**PRD fields, again:** `acceptanceCriteria` gets fixed; `description`, `actionItems` and
`details` do not (SCP-RELAYRES-005 description, SCP-006 actionItems/details). `result` was
correctly rewritten this time. Check all six fields.

**Spec rename with no code counterpart:** §22's `ContextDiscoverySource` variant
`DhtDidDocument` → `DidDocumentBroadcastList` (and wire string `dht_did_document` →
`did_document_broadcast_list`) landed in the spec with zero code changes and no story.
`resolve_contexts_from_did` (`scp-runtime/src/discovery/dht_context.rs`) still reads
`SCPBroadcastContext` off a Mainline resolution — a relay-layer-only entry — so the path
returns empty by construction.

See [[adr057_transport_wasm_surface_parity]] for the same shape at the code layer:
an amendment lands on the primary artifact and its structural twins keep the old rule.
