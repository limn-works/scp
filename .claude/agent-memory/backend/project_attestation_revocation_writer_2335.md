---
name: project-attestation-revocation-writer-2335
description: Issue #2335 finding 13 (per-context attestation revocation list had two readers, no writer) resolved by wiring a writer into FFI verify-on-ingest, not by making a checker fail closed
metadata:
  type: project
---

Alec decided that issue #2335, finding 13 — a per-context attestation revocation
list carrying two readers and no writer outside test code — gets a WRITER on an
FFI verify-on-ingest path, in `crates/scp-ffi/common/src/trust_store.rs`
(`verify_and_cache_attestations`).

**Why:** Alec rejected a second remedy that issue #2335 offered, making a checker
fail closed, and stated his reason: an empty revocation map would then mean
"every attestation is revoked", which zeroes every honest subject's trust rather
than protecting anyone. He wrote "Do NOT re-litigate that choice."

**How to apply:** Treat a writer as settled for that list. A write fires only
when an ingest entry's own signed `revocation_status` reads `Revoked` AND
`verify_attestation_with_revocation` returned `TrustError::AttestationRevoked`.
That pairing is load-bearing: `verify_attestation_with_revocation` in
`crates/scp-protocol/src/trust/attestation.rs` checks an Ed25519 signature as
step 1, compares `revoked_by` against `issuer` at step 4 (raising
`AttestationRevocationInvalid` on mismatch), and consults an external checker
only at step 5, so a step-5 hit against a list an earlier write produced cannot
trigger another write. Anyone reordering those steps breaks that writer's
soundness. Related: [[feedback-worktree-absolute-path]].
