---
name: custody-violation-signing
description: ScpCustodyViolationAttestation and CounterAttestation §9.5.1 signing preimages, their two domain separators, and their verifiers (issue #2335 finding 11)
metadata:
  type: project
---

# Custody-violation signing construction (issue #2335 finding 11)

Before this change, `ScpCustodyViolationAttestation.verifier_signature` and
`CounterAttestation.signature` were checked only for non-emptiness, so any party
could mint a record naming any subject. Two doc comments asserted guarantees no
code delivered (contradiction X15 in issue #2335).

**Why:** ADR-039, shared-DID human-agent identity model (`.docs/adrs/phase-1.md`,
line 1231), enforcement-stack layer 4, makes a custody violation a permanent
record one verifier writes about a non-consenting subject, so a reader must be
able to establish authorship and detect post-signature alteration.

**How to apply:** when touching either type, keep every field except that
record's own signature inside its preimage, and keep both separators unique.

## Domain separators (both registered in spec §9.18.2)

- `"SCP-CUSTODY-VIOLATION-V1:"` — `CUSTODY_VIOLATION_DOMAIN`
- `"SCP-COUNTER-ATTESTATION-V1:"` — `COUNTER_ATTESTATION_DOMAIN`

## Preimage layouts (spec §9.5.2)

`ScpCustodyViolationAttestation`, 7 fields: `subject_did` VarBytes, `timestamp`
U64, a **one-byte variant discriminator** (`0x00` CategoryAViolation, `0x01`
AttestationMismatch), that variant's three VarBytes payload fields,
`verifier_did` VarBytes. Discriminator is load-bearing: without it, a
`CategoryAViolation` whose three fields carry the same bytes as an
`AttestationMismatch` hashes identically and one variant's signature transfers.

`CounterAttestation`, 4 fields: `subject_did`, `violation_reference`,
`explanation` (all VarBytes), `timestamp` U64. **No `signing_key_id` field** —
a subject naming its own fragment inside a record it also signs can name
`#active` while signing with `#agent`. ADR-039 criterion 18's `#active`
assignment is enforced by which key a caller resolves and passes.

## Known-answer hashes (pinned in tests)

- violation, subject `did:dht:subject` / ts 1700000000 / `did_document_update` /
  `#agent` / evidence `DEADBEEF` / verifier `did:dht:verifier`:
  `6f83b1abd686f68b2fb9668e37e7712f296ca8a777bd3ae1e97a9f3109da906f`
- counter, `did:dht:subject` / `sha256:abc123` / `key rotated` / 1700001000:
  `49f87b64b1d023944eaef1c6a34de07d0c32ef92d601d79fa51a07a7d55c7fbc`

## enforce_category_a

Its fifth parameter was `_evidence_signature` and was dropped. It now lands in
`CustodyViolationResult.signature_evidence`, and
`CustodyViolationResult::into_category_a_violation()` moves those bytes into
`CustodyViolationType::CategoryAViolation.signature_evidence`. Signature
unchanged, so no call site needed editing — both production call sites
(`envelope/inner/mod.rs` `enforce_inner_envelope_category_a`,
`crypto/sender_keys/key_protocol_verify.rs` `enforce_sender_key_category_a`)
already passed real signature bytes.

## Gotcha

The module doc previously cited ADR-039 as living in `.docs/adrs/phase-6.md` and
pointed at spec §3.6 (Social Graph). Both references were wrong. ADR-039 is
`.docs/adrs/phase-1.md` line 1231, "Shared-DID Human-Agent Identity Model".
