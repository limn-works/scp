---
name: custody-violation-signing
description: ScpCustodyViolationAttestation and CounterAttestation signing preimages, their domain separators, the verified newtypes, violation_reference derivation, and §25.25 Vectors 38/39
metadata:
  type: project
---

A custody violation (ADR-039 enforcement layer 4, `.docs/adrs/phase-1.md`, "Shared-DID
Human-Agent Identity Model") is a permanent record one verifier writes about a subject who did
not consent, so a reader must be able to establish authorship and detect alteration. The
construction lives in `crates/scp-protocol/src/trust/custody_violation.rs`. When touching
either type, keep every field except the record's own signature inside its preimage, and keep
both separators unique.

**Domain separators** (registered in spec §9.18.2): `"SCP-CUSTODY-VIOLATION-V1:"`
(`CUSTODY_VIOLATION_DOMAIN`) and `"SCP-COUNTER-ATTESTATION-V1:"`
(`COUNTER_ATTESTATION_DOMAIN`).

**Preimages** (spec §9.5.2):
- `ScpCustodyViolationAttestation`: `subject_did` VarBytes, `timestamp` U64, a one-byte
  variant discriminator (`0x00` CategoryAViolation, `0x01` AttestationMismatch), that
  variant's three VarBytes fields, `verifier_did` VarBytes. The discriminator is
  load-bearing: without it, two variants carrying the same three byte strings hash
  identically and one variant's signature transfers to the other.
- `CounterAttestation`: `subject_did` VarBytes, `violation_reference` Fixed32,
  `explanation` VarBytes, `timestamp` U64. It has no `signing_key_id` field on purpose: a
  subject naming its own fragment inside a record it also signs could name `#active` while
  signing with `#agent`. Which key the caller resolves enforces `#active`.

**`violation_reference`** is `ScpCustodyViolationAttestation::signing_hash()` of the contested
record, typed `[u8; 32]`. `CounterAttestation::referencing(&violation, ...)` is the only
constructor and derives both `subject_did` and `violation_reference` from the violation, and
`VerifiedCounterAttestation::answers` rechecks both. The derivation omits
`verifier_signature` deliberately, so a verifier that re-signs identical facts under a rotated
key keeps existing counter-claims pointed at the record.

**Verified newtypes (do not weaken):** `VerifiedCustodyViolation` and
`VerifiedCounterAttestation` are constructed only by `verify(record, public_key)`; the
record types' signature-check methods are module-private; neither newtype implements
`Deserialize`, so a verified value cannot arrive from the wire; `ViolationStore` accepts only
verified values. `validate_field_shape()` (renamed from `validate()`) checks shape only.

**Known-answer vectors** (spec §25.25, pinned by `vector_38_*` / `vector_39_*` tests): Vector
38 preimage 196 bytes, hash `f71802b4a211df2a354484e410e0a16ce4865b9fdbeed4e6a6eaaf930838725a`;
Vector 39 preimage 147 bytes, hash
`7e12cde18598a11b6c270d756029e437d546c2231731f2b2add6ef41c1eb5af1`. Keys follow §25.2:
primary = verifier, secondary = subject `#active`, tertiary = subject `#agent`.
