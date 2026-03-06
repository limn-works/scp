# Loom Status

## Failing Tests
None — full workspace test suite green (3000+ tests pass, 0 failures). Clippy clean with CI features.

## Uncommitted Changes
None — all changes committed. Working tree clean.

## Fixed This Iteration
N/A — no prior failures existed.

## Tests Added / Updated
- 7 wire format compliance tests (serde rename verification)
- Dedup TTL test updated for 24hr window
- 26 sender key test sites migrated from serde_json to rmp_serde
- Legacy serde defaults test rewritten for MessagePack compatibility
- Future-timestamp block notification rejection test
- Same-target RemoveMember conflict detection test
- RotateContentKeys conflict detection test
- 5 sender key request freshness/nonce replay tests (HandleRequestParams API)
- 4 MessageType canonical hash tests (tamper detection, Signaling variant, different-type signatures, msgpack roundtrip)
- Broadcast seal/open tests updated with signing key parameters
- Broadcast signature verification and replay detection tests
- Phase1 integration test updated to MessagePack deserialization

## Work Summary

### Phase 0: COMPLETE — 8 spec fix lanes

| Lane | Issue(s) | Commit |
|------|----------|--------|
| S-B | #380 (UCAN nonce format) | aa92b92 |
| S-C | #378 (Protocol versioning §13) | 23c4b32 |
| S-E | #372 (Identity private state) | f8bbc6e |
| S-F | CRYPTO-03/04/18 (HPKE + nonce) | e6ecaa3 |
| S-G | #381 (Sync anti-replay) | 8c7ae18 |
| S-H | #374 (Context nesting eligibility) | 5c79ab7 |
| S-I | #379 (§15 erasure clarification) | aeaf5f9 |
| S-A, S-D | Pre-existing | Already done |

### Phase 1: COMPLETE — all 7 lanes

| Issue | Description | Commit |
|-------|------------|--------|
| #345 | serde rename (ref_id→ref, event_type→type) | af4192c |
| #313 | Dedup cache TTL 1hr→24hr | 2444c9a |
| #348 | ProtocolStore positional→named MessagePack | d174211, 34d05b2 |
| #354 | Missing conflict detection pairs | 38fe1cf |
| #351 | deny_unknown_fields on InnerEnvelope | 26e2222 |
| #312 | HPKE domain separator alignment | 53ed083 |
| #346 | Sender key JSON→MessagePack + all 4 findings | 7f341b8, 5fb0266 |
| #290 | MessageType into InnerEnvelope + canonical hash | 5f88141 |
| #352 | BroadcastEnvelope missing fields + signatures | c78f1b6 |
| #353 | block_subscriber per-author scope | c78f1b6 |
| #350 | Replace stub RoleDefinition/ToolRegistration | dd392ae |
| #355 | Wire missing governance fields | dd392ae |
| #301 | Wire real metrics to dev API + blob backends | cf3cc06 |

### Review Fixes (post-Phase 1)

| Finding | Fix | Commit |
|---------|-----|--------|
| deny_unknown_fields on 4 sender key wire types | Added to SenderKeyEpochAdvance, SenderKeyRequest, SenderKeyResponse, BlockNotification | 81185a1 |
| handle_sender_key_request no timestamp/nonce validation | Added freshness check + NonceDedup replay via HandleRequestParams | 81185a1 |
| Integer overflow in future-timestamp check | saturating_add | 81185a1 |
| Missing future-timestamp test | Added | 81185a1 |
| Missing conflict detection tests | Added same-target RemoveMember + RotateContentKeys | 81185a1 |
| BlockNotification missing signing_key_id | Added per ADR-007 §6 | 5fb0266 |
| Nonce fields missing serde_bytes | Added to SenderKeyRequest.nonce + SenderKeyResponse.request_nonce | 5fb0266 |
| Store version bump unnecessary | Reverted to v1 (nothing shipped) | cd14abc |
| Integration test using JSON for MessagePack data | Fixed to rmp_serde | a8d2051 |

### Phases 2-12: NOT STARTED
See `.docs/prod-readiness-exec-plan.md` for the full 12-phase plan.

## Issues Commented (19)
#290, #301, #312, #313, #345, #346, #348, #350, #351, #352, #353, #354, #355, #372, #374, #378, #379, #380, #381
