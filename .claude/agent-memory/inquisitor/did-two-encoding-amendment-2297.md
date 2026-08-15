---
name: did-two-encoding-amendment-2297
description: Interrogation of the #2297 two-DID-document-encodings amendment (commits 78c72b6e7/5bc5ad838/40f422461) — core decision sound and externally forced, but 12 clauses carry expired or self-falsifying premises
metadata:
  type: project
---

Commits `78c72b6e7`, `5bc5ad838`, `40f422461` (on `aeba9c24f`) split the DID document into two
encodings: full JSON on the SCP relay layer (262,039 B), a did:dht DNS-packet "bootstrap core"
on Mainline (1,000 B). They delete the old cross-layer byte-identity MUST and the cross-layer
highest-sequence-wins rule.

**Why:** BEP44 caps the Mainline payload at 1,000 bytes and the smallest document §18.2.2A
permits is 1,255 bytes minified. That is an external constraint, so the two-encoding decision
itself is SOUND and should not be re-litigated.

**How to apply:** the *decision* is settled; the *clauses* are where the rot is. When this area
comes back, check these first rather than re-deriving:

- §18.2.2A `verificationMethod` row ("No other verification methods permitted") directly
  contradicts ADR-003 §4a/§4a′ (`.docs/adrs/phase-1.md:378,387`, retain `#retired-{seq}`, cap 2).
  §18.2.2B calls this "open" while letting the prohibition stand — that is a decision hidden
  inside a declared deferral.
- The retired-key open question is registered in NO `.docs/` artifact.
  `.docs/specs/00-open-questions.md` holds only struck-through Resolved entries.
- ADR-003 §4a/§4a′ still justify the cap-of-2 by "DHT size constraints." That premise expired
  with this amendment; the structurally identical ADR-039 agent-key argument WAS corrected in
  the same file. Classic fixed-one-side-left-the-twin.
- §3.10.1 ("a resolver that needs only the bootstrap core takes whichever layer answers first")
  contradicts §3.10.7's harm-bounding sentence ("a verifier that needs a current `#active`
  therefore resolves the relay layer"). `#active` is a core element, so a rotation that reaches
  relays but not Mainline is accepted stale with nothing to reject it.
- §3.10.8's "suppress ALL relays AND all DHT nodes" and §11.2.2's twin survived unamended and
  are now false for anything outside the core.
- §3.10.10's `ResolvedDidDocument { document: DidDocument, completeness }` enforces
  "unresolved, not absent" in prose across six MUSTs. It is the amendment's load-bearing
  mechanism and the one place it chose documentation over the type system.

Related: [[scp-out-046-streaming-saga-seal-fsm]], [[adr057-reciprocal-announce-mesh]].
