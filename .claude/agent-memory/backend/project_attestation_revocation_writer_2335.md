---
name: project-attestation-revocation-writer-2335
description: Per-context attestation revocation list gets its writer on FFI verify-on-ingest, not a fail-closed checker; the step order that keeps the writer sound; an agent, not Alec, wrote the ruling
metadata:
  type: project
---

Issue #2335, finding 13 — a per-context attestation revocation
list carrying two readers and no writer outside test code — got a WRITER on an
FFI verify-on-ingest path (the remedy an orchestrating agent chose; the "Do NOT
re-litigate" line was written by that agent, not by Alec), in `crates/scp-ffi/common/src/trust_store.rs`
(`verify_and_cache_attestations`).

**Why:** the second remedy issue #2335 offered, making a checker fail closed,
would make an empty revocation map mean "every attestation is revoked", which
zeroes every honest subject's trust rather than protecting anyone.

**How to apply:** The writer is what main ships for that list. A write fires only
when an ingest entry's own signed `revocation_status` reads `Revoked` AND
`verify_attestation` returned `TrustError::AttestationRevoked`.
That pairing is load-bearing: `verify_attestation` (the only verifier; it takes a
required `&dyn AttestationRevocationChecker`) in
`crates/scp-protocol/src/trust/attestation.rs` checks an Ed25519 signature as
step 1, compares `revoked_by` against `issuer` at step 4 (raising
`AttestationRevocationInvalid` on mismatch), and consults an external checker
only at step 5, so a step-5 hit against a list an earlier write produced cannot
trigger another write. Anyone reordering those steps breaks that writer's
soundness.
