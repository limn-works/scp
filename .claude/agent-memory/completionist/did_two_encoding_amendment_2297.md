---
name: did-two-encoding-amendment-2297
description: Review of the #2297 DID two-encoding amendment (commits 78c72b6e7/5bc5ad838/40f422461+) — where the deleted one-document-two-layers rule survived elsewhere in .docs/
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
deleted rule — the amendment's own §3.10.7/§18.2.2A wording is what governs. The places
the amendment did NOT reach on first pass, and the class each represents:

- `.docs/adrs/ADR-062-...md:41,96` — the E4 `NoOpRelayQuerier` "not a nullifier" verdict
  rests on "resolution runs DHT-only, authenticity/reachability/freshness preserved."
  Under two encodings a DHT-only resolution returns the bootstrap core only, so every
  relay-layer-only field is permanently unresolvable. **A security classification resting
  on a deleted premise is the highest-value class to hunt after any resolution-model
  amendment.**
- `.docs/specs/11-prior-art.md:155-160` and `03-identity.md:1025,1026,1107` — "the other
  layer serves" survivals in prose *near* amended paragraphs. Amending a numbered item in
  a list does not amend the unnumbered list above it.
- `.docs/specs/03-identity.md:1117` — the §3.10.12 implementation-artifacts table still
  said "first-valid-wins" after §3.10.4 replaced it. **Tables at the end of an amended
  section are a reliable blind spot.**
- `.docs/prds/reachability.json:665,705` and `relay-did-resolution.json:218,227,270` —
  story `title` and `result` fields carry the deleted rule after `description` and
  `acceptanceCriteria` were rewritten. **Amend all four fields, not two.**
- `.docs/specs/22-human-readable-addressing.md:1131` — a `DhtDidDocument` enum variant
  named after the layer that no longer carries the entry it names.

See [[adr057_transport_wasm_surface_parity]] for the same shape at the code layer:
an amendment lands on the primary artifact and its structural twins keep the old rule.
