---
name: Fuzzing Plan Security Review
description: Security review of the SCP fuzzing infrastructure plan -- coverage gaps, missing targets, invariant checks
type: project
---

Reviewed 2026-04-12. Plan at `.claude/plans/idempotent-stirring-fox.md`.

## Key Findings (12 total)

HIGH x4:
- F-01: Missing InnerEnvelope::from_bytes fuzz target (inner envelope is the real trust boundary after MLS decryption)
- F-02: Missing sender key + access key wire type fuzz targets (SenderKeyDistributionMessage, SenderKeyRequest, AccessKeyRequest -- all lack deny_unknown_fields)
- F-03: Missing Merkle proof verification fuzz targets (InclusionProof path Vec unbounded, ConsistencyProof leaf_hashes Vec unbounded)
- F-04: ClientMessage/RelayMessage from_bytes has NO pre-deser size check (unlike OuterEnvelope which checks MAX_ENVELOPE_SIZE first)

MEDIUM x6:
- F-05: Sanitizer strategy incomplete (ASan default OK, skip MSan, add UBSan weekly)
- F-06: ArbUcanToken structured fuzzing won't reach deep validate_ucan paths (need signed-token generation in harness)
- F-07: Missing Nostr/CoAP/QUIC transport parser fuzz targets
- F-08: Missing canonical hash stability invariant (same logical value -> same hash, even from different byte encodings)
- F-09: Missing security-critical semantic invariants (expired tokens always rejected, relay scheme always wss://, etc.)
- F-10: CI corpus caching uses run_id -- prevents cross-run accumulation (need restore-keys prefix match)

LOW x2:
- F-11: No max_len limits per target
- F-12: Seeds should include known-bad inputs from existing tests, not just valid instances

## Coverage Gap Priority
Highest value missing targets: InnerEnvelope > SenderKeyDistributionMessage > AccessKeyRequest > Merkle proofs > Nostr/CoAP

**Why:** build_hpke_info already known to lack length separators (iteration 17 audit). Sender key types lack deny_unknown_fields (production readiness audit). These are the most likely to yield real bugs.

**How to apply:** When plan is updated, verify these targets are added in priority order.
