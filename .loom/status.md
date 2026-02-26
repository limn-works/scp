# Loom Status

## Failing Tests
None. All 1,920 workspace tests pass (1,444 scp-core + 158 scp-mcp + 64 scp-node + 10 scp-media + 44 scp-platform + 189 scp-transport + 2 scp-testing + doctests).

## Uncommitted Changes
None. All changes committed.

## Fixed This Iteration
- SCP-177: Completed manually after subagent left it incomplete. Added `decrypt_with_sender_key()` to encrypt.rs, `verify_sender_in_group()` to outer.rs, `UnknownSender` error variant, `sign()`/`signer_public_key()` to ScpMlsGroup, `import_ed25519_key()` to InMemoryKeyCustody, `MlsGroupKeyCustody` adapter in integration tests. All call sites updated. Commit `d750282`.

## Tests Added / Updated
- `crates/scp-core/src/envelope/outer.rs`: 2 new SCP-177 tests (`open_envelope_resolves_sender_key_from_group`, `open_envelope_rejects_unknown_sender_did`), all existing tests updated for new `open_envelope` signature (no `sender_public_key` param).
- `crates/scp-testing/tests/integration/phase1.rs`: Updated to use `MlsGroupKeyCustody` adapter and new `open_envelope` signature.
- `crates/scp-core/src/crypto/ucan/nonce.rs`: 6 capacity tests
- `crates/scp-core/src/context/tools/schema.rs`: 22 JSON schema validation tests
- `crates/scp-core/src/well_known.rs`: 5 DHT cross-verification tests
- `crates/scp-transport/src/native/client.rs`: 3 blob integrity tests
- `crates/scp-transport/src/manager.rs`: Updated for &self signatures + concurrency test
- `crates/scp-mcp/src/server.rs`: 4 validation tests updated

## Tool-Gated Stories
None.

## Subagent Outcomes
1. **SCP-185** (send_to_context &self) — **DONE**. Commit `56f48af`.
2. **SCP-190** (nonce tracker capacity) — **DONE**. Commit `2c0fda8`.
3. **SCP-193** (blob integrity) — **DONE**. Commit `1139e84`.
4. **SCP-188** (well-known DHT) — **DONE**. Commit `01f0643`.
5. **SCP-189** (JSON schema validation) — **DONE**. Commits `dfa16c3`, `b22fa40`, `24e6eae`.
6. **SCP-177** (open_envelope sender key) — **DONE** (manually completed). Commit `d750282`.

## Pending Stories
SCP-187 (Consolidate DID type alias) is the last correctness-gate story. After that, 20 stories remain in gate-harden (SCP-191 through SCP-211).
