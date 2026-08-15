---
name: did-document-membership-criteria
description: The three criteria deciding what a SCP DID document carries, and the one retention question that stays open for Alec
metadata:
  type: project
---

`.docs/specs/18-addressability-and-deployment.md` §18.2.2B states three criteria, applied in order, deciding what a DID document carries. Before this, no rule stated it, which is why the document accreted.

1. **Owner-asserted, not participant-recorded.** The owner produces a value by computing and signing it; other participants produce a value by recording the identity's behaviour. Participant-produced values live in context state (§9.3's storage split); the document may carry an owner-asserted pointer to where a verifier fetches them. Second half: an owner-produced value asserting something outside the identity's own configuration carries a proof a verifier checks without trusting the owner — otherwise the criterion admits a self-declared reputation number.
2. **A maximum count the owner cannot raise.** An entry class whose count grows when the owner takes one more repeatable action becomes **one** pointer entry. Two classes fail today and become pointers: the per-context `SCPBroadcastContext` entry (§5.14.11 mechanism 1) and the device-attestation proof.
3. **Mainline bootstrap-core membership.** Clause (a) admits what a resolver needs to reach a relay — the relay list, because §18.5.1 makes Mainline resolution level 2, the first place an SDK learns of any relay. Clause (b) admits the verification material *every* identity carries: `#active` and the `PreRotationCommitment` entry. `#0` carries no key bytes (the DID string encodes them) but the DNS packet still emits a `k0` record. `#agent` is excluded because ADR-039 makes it optional; a core-only resolver reports it unresolved and fetches from a relay.

**Why criterion 3 has two clauses:** an earlier draft said "needed before any relay answers", which admits the relay list and nothing else — the relay layer's DID record verifies against the DID-string key, never `#active`. That draft was an enumeration standing where a test belonged.

**OPEN — Alec's call, blocking.** Whether content signatures verify against retired verification methods, and if so how retention is bounded (inline under a cap, or behind a pointer). §18.2.2A's `verificationMethod` row still permits no verification method beyond `#0`, `#active`, `#agent`. Three clauses move together when it lands: that row, CONF-001 and CONF-003 in §26.3. The plan of record marks this open; do not resolve it. See [[did-two-layer-encoding-settled]].
