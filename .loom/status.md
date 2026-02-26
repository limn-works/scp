# Loom Status

## Failing Tests
None. All 1,970 workspace tests pass (1,493 scp-core + 158 scp-mcp + 64 scp-node + 10 scp-media + 44 scp-platform + 192 scp-transport + others).

## Uncommitted Changes
None. All changes committed.

## Fixed This Iteration
- `verify_expiry_rejects_epoch_zero_token` — updated assertion from `TokenExpired` to `InvalidTimeRange` since the new `nbf >= exp` check fires first when both are 0.

## Tests Added / Updated
- `crates/scp-core/src/crypto/ucan/validate.rs`: 3 new tests for nbf>=exp (rejects nbf>exp, rejects nbf==exp, accepts nbf<exp). Updated epoch-0 test expectation.
- `crates/scp-core/src/crypto/ucan/revoke.rs`: Updated `success_path_final_state_is_revoked` to use `&UcanPayload` + content-hash CID. New tests for CID-based revocation.
- `crates/scp-core/src/crypto/sender_keys/encrypt.rs`: Test for reference return from store lookup.
- `crates/scp-core/src/crypto/sender_keys/key_protocol.rs`: Test for epoch overflow at u64::MAX.
- `crates/scp-core/src/identity/dht.rs`: Tests for bs58 round-trip encoding.
- `crates/scp-core/src/identity/cache.rs`: 3 boundary tests (seq > accepted, seq == rejected, seq < rejected).
- `crates/scp-core/src/identity/document.rs`: 3 tests for MigrationProof signature length (64 accepted, 63 rejected, 65 rejected).
- `crates/scp-core/src/context/close.rs`: Tests for SystemClose and Expired event variants.

## Tool-Gated Stories
None.

## Subagent Outcomes
1. **SCP-192** (UCAN validation nbf>exp + CID) — **DONE**. Added InvalidTimeRange check, content-hash CID revocation. Required merge conflict resolution for now_secs() Result type and revoke_ucan signature.
2. **SCP-197** (SenderKeyStore optimization) — **DONE**. Store returns &SenderKey reference, epoch uses checked_add with EpochOverflow error.
3. **SCP-198** (Replace base58btc with bs58) — **DONE**. Added bs58 0.5 workspace dep, replaced hand-rolled encoder.
4. **SCP-201** (DID cache seq fix) — **DONE**. Changed >= to > in cache comparison. 3 boundary tests.
5. **SCP-202** (MigrationProof signature [u8;64]) — **DONE**. Custom serde for fixed-size array, length validation on deser.
6. **SCP-203** (Replace sentinel DIDs) — **DONE**. Added SystemClose and Expired variants to ContextEvent, replaced all sentinel strings.

## Remaining Stories
10 stories remain: SCP-200, SCP-204, SCP-205, SCP-206, SCP-207, SCP-208, SCP-209 (blocked by 207+208), SCP-210, SCP-211.
