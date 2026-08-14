# ADR-056 Canonical Context Identity Chokepoint + Recovery Fail-Open Fix (PR-A rev6, 3a9d7d91d) -- 2026-06-29 -- ZERO FINDINGS

## What
ADR-056: canonical context identity = 32-byte digest; id string = hex(digest). Resolution from
id-string -> keying bytes funnels through ONE chokepoint `context_id_to_bytes` (state.rs:2072):
if 64-char all-lowercase-hex -> hex::decode to digest; else SHA-256(id) via raw primitive fallback.
The raw `scp_protocol::context::context_id_bytes` double-hashes a real id (SHA-256(hex(digest))) ->
keys wrong slot = silent fail-open. HEAD commit 3a9d7d91d fixes a HIGH regression where
`recovery_send_notification_direct` (supervisor.rs:3540) had been flipped to the raw primitive on a
FALSE premise (only synthetic identity-private-state reaches it).

## Verification (all confirmed)
- Chokepoint (state.rs:2072-2089): strict 64+lowercase-hex guard, total/panic-free (no unwrap),
  fallthrough to raw primitive keeps non-64-hex byte-identical. Correct.
- Recovery senders BOTH key via chokepoint: registered-actor handler
  trust_recovery_helpers::recovery_send_notification (line 322 context_id_to_bytes) AND
  recovery_send_notification_direct (now context_id_to_bytes at ~3568). They key the SAME slot.
- Routing: dispatch_trust_recovery_command (supervisor.rs:3230) -> if no actor -> direct path ->
  RecoverySendNotification arm (3467) -> recovery_send_notification_direct. revoke_ucans (seq 1,
  recovery.rs:953) + rotate_key_packages (seq 2, recovery.rs:1003) dispatch to REAL member ctx with
  NO registration gate -> hit direct path -> WAS double-hashing -> now decoded. mls_update (seq 0)
  gated by RecoveryAdvanceEpoch -> ContextNotRegistered (safe). PSK identity-private-state = 22-char
  label -> SHA-256 fallback (unchanged). Fix COMPLETE across all recovery senders.
- ALL 3 production seal sites key via chokepoint: trust_recovery_helpers:352, messaging_helpers:206,
  supervisor:3597. No residual fail-open keying path.
- Residual raw context_id_bytes calls: ONLY production site = state.rs:2088 (resolver's own
  fallback) + builder.rs:766 (local shadow fn -> chokepoint). All other hits are #[cfg(test)]
  (provider.rs:4273/4848, export_import.rs all, state.rs:2276+ canonical_context_id_tests,
  agent_binding_pipeline_tests.rs, supervisor.rs:14123 regression test, builder.rs:989 test).
- broadcast_routing_id (protocol mod.rs:130) calls raw primitive = ROUTING id (subscriber
  addressing, SHA-256(id) per spec §5.14), NOT crypto keying; symmetric send+subscribe. Not a leak.
- FFI bridges (PyO3/NAPI/UniFFI event_log + testing): all 10 sites rerouted raw -> chokepoint
  scp_core::context::state::context_id_to_bytes. Facade chain intact (scp-core/lib.rs:91
  pub use scp_runtime::context::state; context_id_to_bytes is pub).
- pub surface: context_id_to_bytes already pub; raw primitive visibility unchanged. No new capability.
- Docs steer correctly: raw primitive doc rewritten "do NOT use to key a real context"; routing_id
  doc points to chokepoint.
- Mutation-resistant tests: builder.rs create_context_keys_crypto_under_decoded_digest_not_sha256
  (asserts crypto keyed under digest, EMPTY under SHA-256(id)); supervisor.rs
  recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive (TransportFailed=pass vs
  CryptoFailed=regression). Both genuinely distinguish decode from hash.

## Minor (non-blocking)
- supervisor.rs:3454-3466 inline comment still describes ONLY the synthetic PSK case as reaching the
  RecoverySendNotification direct arm; the function doc (3496-3539) was correctly updated to state
  both shapes. Stale comment, not a defect.

## Posture on removed source-text CI gate
Acceptable: regex pseudo-lexer can't soundly tokenize Rust cfg(test) scope (perpetual fail-open
class); replaced by chokepoint + mutation tests + forthcoming ContextDigest newtype (#1931, makes
raw-primitive keying a compile error). Consistent with OwnedIdentityDid gate drop (#1826).
