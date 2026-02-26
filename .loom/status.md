# Loom Status

## Failing Tests
None. All 1,939 workspace tests pass (1,460 scp-core + 158 scp-mcp + 64 scp-node + 10 scp-media + 44 scp-platform + 192 scp-transport + 2 scp-testing + 5 integration + doctests).

## Uncommitted Changes
None. All changes committed.

## Fixed This Iteration
No previous failures to fix.

## Tests Added / Updated
- `crates/scp-core/src/crypto/ucan/validate.rs`: 5 new tests for circular delegation detection (A->B->C->A cycle, A->B->C no cycle, self-delegation A->A, max depth with seen_issuers, error display).
- `crates/scp-core/src/crypto/mls/credential.rs`: 4 new tests for DID format validation (valid DID accepted, empty rejected, wrong method rejected, missing z-prefix rejected).
- `crates/scp-core/src/crypto/mls/encrypt.rs`, `group.rs`, `key_package.rs`, `ratchet.rs`, `crates/scp-core/src/envelope/outer.rs`, `crates/scp-media/src/keys.rs`, `crates/scp-testing/tests/integration/phase1.rs`: Updated existing test DID strings to valid `did:dht:z...` format.
- `crates/scp-transport/src/native/client.rs`: 3 new tests for pending map cleanup on timeout (timeout_cleans_pending_map, repeated_timeouts_dont_leak, success_still_works_after_fix).
- `crates/scp-transport/Cargo.toml`: Added `test-util` tokio feature for time mocking.

## Tool-Gated Stories
None.

## Subagent Outcomes
1. **SCP-187** (DID newtype consolidation) — **INCOMPLETE**. Subagent defined the newtype in identity/mod.rs but failed to complete all 15+ module migrations within turn limits. Partial changes reverted. Story remains `pending` for next iteration. Recommend running as solo dedicated story.
2. **SCP-191** (UCAN circular delegation) — **DONE**. Added CircularDelegation error variant, HashSet-based cycle detection in verify_delegation_chain. 5 tests. Commit `ff8b4e2`.
3. **SCP-194** (Merkle non-membership proofs) — **DONE**. Added prove_absence/verify_absence with AbsenceProof struct using sorted-neighbor approach. 7 tests. Changes already in tree from subagent.
4. **SCP-195** (TTL extension member validation) — **INCOMPLETE**. Subagent reported completion but changes were entangled with SCP-187 partial DID newtype migration and had to be reverted. Story remains `pending`.
5. **SCP-196** (Clean pending request map on timeout) — **DONE**. Timeout branch removes pending entry. 3 tests with tokio test-util time mocking. Commit `7b20307`.
6. **SCP-199** (DID format validation on ScpCredential) — **DONE**. Validates `did:dht:z` prefix, InvalidDidFormat error. Updated all test DIDs. 4 tests. Commit `7c96024`.

## Pending Stories
SCP-187 (DID newtype consolidation) is the last gate-correctness story — blocked by scope (too large for one subagent pass). After that, 16 gate-harden stories remain: SCP-192, SCP-195, SCP-197, SCP-198, SCP-200, SCP-201, SCP-202, SCP-203, SCP-204, SCP-205, SCP-206, SCP-207, SCP-208, SCP-209, SCP-210, SCP-211.
