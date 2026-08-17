---
name: custody-violation-signing
description: ScpCustodyViolationAttestation and CounterAttestation §9.5.1 signing preimages, their two domain separators, verified newtypes, violation_reference derivation, and §25.25 Vectors 38/39 (issue #2335 finding 11)
metadata:
  type: project
---

# Custody-violation signing construction (issue #2335 finding 11)

Before this work, `ScpCustodyViolationAttestation.verifier_signature` and
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

`CounterAttestation`, 4 fields: `subject_did` VarBytes, `violation_reference`
**Fixed32** (32 raw bytes, no length prefix), `explanation` VarBytes,
`timestamp` U64. **No `signing_key_id` field** — a subject naming its own
fragment inside a record it also signs can name `#active` while signing with
`#agent`. ADR-039 criterion 18's `#active` assignment is enforced by which key a
caller resolves and passes.

## violation_reference derivation (spec §9.5.2, normative)

`violation_reference` == `ScpCustodyViolationAttestation::signing_hash()` of the
contested record. Type is `[u8; 32]`, never a free-form `String`.

- `CounterAttestation::referencing(&violation, explanation, timestamp, signature)`
  is the ONLY constructor; it derives both `subject_did` and
  `violation_reference` from a violation record, so an author cannot invent one.
- `VerifiedCounterAttestation::answers(&VerifiedCustodyViolation)` rechecks both
  reference equality and subject equality, returning
  `ViolationReferenceMismatch` / `SubjectMismatch`.
- Omitting `verifier_signature` from that derivation is deliberate: one verifier
  re-signing identical facts under a rotated key keeps a published counter-claim
  pointed at that record. A digest over a serialized record including the
  signature was rejected — it separates two records only when one verifier signs
  identical facts under two keys, and it needs a third domain separator.

## Verified newtypes (type-level fix, do not weaken)

`VerifiedCustodyViolation` / `VerifiedCounterAttestation` wrap their records;
`verify(record, public_key)` is the only constructor. Both record types'
`verify_*_signature` methods are **module-private**, so obtaining a verified
value is the only way to run a signature check. Neither newtype implements
`Deserialize`, so a verified value cannot arrive from the wire. `ViolationStore`
accepts only verified values. `validate()` was renamed
`validate_field_shape()` on both record types, because `validate` read as an
authenticity check to SDK consumers.

## CategoryARejection (ADR-039 layer 3)

ADR-039 layer 3 reads "The attempt is both rejected and logged as a custody
violation", so layer 3 records. `enforce_inner_envelope_category_a` and
`enforce_sender_key_category_a` now return `Result<(), CategoryARejection>`:
`Recorded { error_message, violator_did, violation }` carries the
`CustodyViolationType::CategoryAViolation` holding observed signature bytes;
`EvidenceUnusable { .., reason }` fires when observed evidence is empty. Both
convert into `EnvelopeError` / `SenderKeyError` through `From`, which keeps the
message and drops the record. `CategoryARejection::from(CustodyViolationResult)`
is what finally calls `CustodyViolationResult::into_category_a_violation`.

## §25.25 known-answer vectors (spec 25)

Vector 38 (violation) and Vector 39 (counter) use §25.2 keys: primary =
verifier, secondary = subject `#active`, tertiary = subject `#agent` (matching
§25.9 Vector 20). §25.2 gained a tertiary seed block
(`0xc5aa8d…58f7`, RFC 8032 §7.1 TV3) because §25.9 published that public key
with no seed.

- Vector 38 preimage 196 bytes, hash
  `f71802b4a211df2a354484e410e0a16ce4865b9fdbeed4e6a6eaaf930838725a`
- Vector 39 preimage 147 bytes, hash
  `7e12cde18598a11b6c270d756029e437d546c2231731f2b2add6ef41c1eb5af1`

Pinned by `vector_38_*` / `vector_39_*` tests in `custody_violation.rs`. The
earlier ad-hoc in-crate KATs (`6f83b1ab…`, `49f87b64…`) were replaced by these,
and the counter hash changed anyway when field 2 became Fixed32.

## Gotcha

The module doc previously cited ADR-039 as living in `.docs/adrs/phase-6.md` and
pointed at spec §3.6 (Social Graph). Both references were wrong. ADR-039 is
`.docs/adrs/phase-1.md` line 1231, "Shared-DID Human-Agent Identity Model".
