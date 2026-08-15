---
name: did-document-membership-criteria
description: The three criteria deciding what a SCP DID document carries, and the one retention question that stays open for Alec
metadata:
  type: project
---

`.docs/specs/18-addressability-and-deployment.md` §18.2.2B states three criteria, applied in order, deciding what a DID document carries. Before this, no rule stated it, which is why the document accreted.

1. **Can a reader check this value without trusting the owner who published it?** Two things make a value checkable: it is the identity's own configuration (keys, relays, endpoints, the pre-rotation commitment) where the owner's authority is total, or it asserts a fact the owner does not control and carries a proof from whoever does (platform attestation, device attestation, an endorser's signature, §9.12's migration proof). A value satisfying neither is excluded — a self-declared trust score, and anything other participants compute from behaviour (§9.3 puts those in context state; the document may point at them). An earlier draft tested *who produced* the value, which answered the endorsements case twice and disagreed with §9.3.
2. **A maximum count the owner cannot raise.** An entry class whose count grows when the owner takes one more repeatable action becomes **one** pointer entry. Two classes fail today and become pointers: the per-context `SCPBroadcastContext` entry (§5.14.11 mechanism 1) and the device-attestation proof.
3. **Mainline bootstrap-core membership.** Clause (a) admits what a resolver needs to reach a relay — the relay list, because §18.5.1 makes Mainline resolution level 2, the first place an SDK learns of any relay. Clause (b) admits the verification material *every* identity carries: `#active` and the `PreRotationCommitment` entry. `#0` carries no key bytes (the DID string encodes them) but the DNS packet still emits a `k0` record. `#agent` is excluded because ADR-039 makes it optional; a core-only resolver reports it unresolved and fetches from a relay.

**Why criterion 3 has two clauses:** an earlier draft said "needed before any relay answers", which admits the relay list and nothing else — the relay layer's DID record verifies against the DID-string key, never `#active`. That draft was an enumeration standing where a test belonged.

**TWO OPEN QUESTIONS — Alec's call. Both are registered in `.docs/specs/00-open-questions.md`; read them there, do not resolve them.**

1. **Retired verification methods.** Do content signatures verify against them, and what bounds retention? §18.2.2A's `verificationMethod` row is **suspended** for `#retired-*` in both directions — it neither permits nor forbids them — because leaving its old "No other verification methods permitted" standing was the negative answer written as a MUST, and it contradicted ADR-003 §4a/§4a′ which require retention. ADR-003's count of 2 is not an answer: its "within DHT size constraints" rationale died when §18.2.2C moved retired keys to the relay layer's 262,039-byte bound.
2. **Does the bootstrap core carry `#agent` and `alsoKnownAs`?** Excluding them costs: an `#agent`-signed artifact cannot be verified when all relays are down, so §9.7.1 fails closed and the identity is unadmittable; and a migrated identity looks live to a Mainline-only resolver, which is §9.12's `#0`-compromise recovery path. Size is not the reason — the core is 676 bytes against a 1,000-byte cap and one more key record costs ~70.

See [[did-two-layer-encoding-settled]].
