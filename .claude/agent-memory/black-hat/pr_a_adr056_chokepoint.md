---
name: pr-a-adr056-chokepoint
description: PR-A (#123/#1924) ADR-056 canonical context identity; chokepoint context_id_to_bytes; recovery_send_notification_direct double-hash fix (HEAD 3a9d7d91d) reviewed CLEAN
metadata:
  type: project
---

# PR-A ADR-056 canonical context identity (#123 / #1924)

ADR-056: a context's canonical identity IS its 32-byte digest; id string = `hex(digest)`.
Chokepoint resolver `crate::context::state::context_id_to_bytes` (state.rs:2072):
strict 64-lowercase-hex → `hex::decode` to digest; else raw `SHA-256(id)` fallback
(`scp_protocol::context::context_id_bytes`). Total/no-panic. The raw primitive
double-hashes a real id (`SHA-256(hex(digest))`) → wrong slot → fail-open.

## HEAD fix (3a9d7d91d) — VERIFIED CORRECT + mutation-proven
`recovery_send_notification_direct` (supervisor.rs:3540) was flipped to the raw
primitive under a FALSE "only synthetic identity-private-state reaches here" comment.
Reality: routing is `dispatch_trust_recovery_command` (supervisor.rs:3230) → actor
mailbox IF `lookup(ctx_id)` registered, ELSE `_direct`. So ANY real 64-hex member
context with no live actor hits `_direct`. `revoke_ucans` (seq1) + `rotate_key_packages`
(seq2) dispatch real ids with NO registration gate → double-hashed → recovery
notification silently lost (UCANs not revoked / key packages not purged = security
fail-open). seq0 `mls_update`→`RecoveryAdvanceEpoch` is SAFE on direct path: returns
`ContextNotRegistered` at supervisor.rs:3448 before any seal.
Fix routes line 3568 via chokepoint, matching registered-actor handler
`trust_recovery_helpers::recovery_send_notification` (line 322, also chokepoint).
routing_id = `context_routing_id` on both paths (identical). Test
`recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive` IS mutation-
resistant: I reverted line 3568 to raw primitive → test FAILED with the exact
`CryptoFailed: no MLS group` path (proven in isolated worktree, then restored).

## Sibling sweep — ALL keying sites migrated to chokepoint (CLEAN)
send/deliver/build_envelope/snapshot-persist (messaging_helpers), export/import/restore
(lifecycle_helpers), consequence event-log (governance_logic), key_destruction, ttl,
seal/open AAD consistency guards (mls/provider.rs), broadcast_helpers (ALL via
context_id_to_bytes), builder.rs local wrapper (delegates to chokepoint), all 4 FFI
bridges (event_log query/verify + fullstack testing), scp-testing fullstack node.
Sole production raw-primitive call site = the resolver's own fallback (state.rs:2088).
`broadcast_routing_id` (protocol mod.rs:130) correctly stays raw SHA-256 — that's
RELAY ROUTING (no domain sep, spec §5.14), NOT crypto keying.

## Subtleties that are SOUND (not bugs)
- `generate_context_id` (scp-ffi-common) = `hex(OsRng 32 bytes)` = always 64-lowercase-
  hex, so decode round-trips. Uppercase/63/65-len ids correctly hash (test-only ids).
- Standing contexts: keyed by the PREFIXED string `standing-<hex>` via chokepoint →
  falls to `SHA-256("standing-<hex>")` (not bare 64-hex). `derive_standing_context_digest`
  (raw digest from DIDs) is ONLY the saga reservation key + wire derived_context_id,
  NEVER the crypto slot. Internally consistent (create/send/destroy all use same string).
- mls/provider seal/open guard: `hex(ctx_id)` now PASSES the top-of-open resolve guard
  (hex(digest) IS canonical), rejection moves one layer deeper to AEAD AAD mismatch.
  §9.16.1 (AAD binds RAW string) still holds. Dedicated guard test kept with non-64-hex
  mismatch. No fail-open.

VERDICT: nothing actionable. Fix closes the HIGH fail-open; sweep is consistent;
test mutation-resistant (empirically). 8 targeted tests pass.
