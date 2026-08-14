# ADR-056 PR-A rev8 review (recovery chokepoint) — 295bc3154

CLEAN. No actionable defects. `chore/fuzz-pin-nightly` lineage, /tmp/scp-prA-rev8.

## What it does
HEAD commit 295bc3154 routes `recovery_send_notification_direct` (supervisor.rs ~3555)
keying through the ADR-056 chokepoint `context_id_to_bytes` (was raw `context_id_bytes`
in PR-A's own earlier commit — a real-context double-hash fail-open). The direct path is
reached for ANY unregistered context (ADR-049 lazy-spawn): synthetic
`identity-private-state` (PSK §9.12 step 6, hashed) AND real 64-hex member contexts via
revoke_ucans (seq 1) / rotate_key_packages (seq 2), which decode to digest.

## Verified
- Chokepoint (state.rs:2072) total: 64-lowercase-hex→hex::decode→[u8;32], else SHA256.
  Belt-and-suspenders `if let Ok` guards, no panic/unwrap. 6 module tests pass.
- Regression test `recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive`
  (supervisor.rs:14124) genuinely mutation-resistant: seeds MLS group+sender key under
  the DIGEST; with chokepoint seal succeeds→TransportFailed("transport not configured")
  via NotConfiguredTransportProvider; with raw primitive `with_context` finds no entry→
  CryptoFailed("no MLS group")→test panics. Both branches asserted. NOT a tautology.
  PASSES.
- inner.epoch=0 hardcode SAFE: AAD in encrypt_sender_layer binds ctx_str/local_did/
  **sender_key_epoch**/send_sequence — NOT inner.epoch. Confirmed by reading seal
  (provider.rs:1596). Comment ~3473-3481 accurate.
- Both seal+open defense-in-depth guards (provider.rs:1581,1675) switched raw→chokepoint.
  REQUIRED not cosmetic: a real-context seal keyed under digest would be REJECTED by a
  guard recomputing SHA256(hex(digest))≠digest. Guard now recomputes context_id_to_bytes
  → matches by construction. Test renamed open_rejects_...does_not_resolve_to_context_id.
- Test-helper fix `signed_import_export_with_member` (supervisor.rs:12709) keys event-log
  via chokepoint (resolves my prior LOW finding re stale "import path's own derivation"
  comment). Both rejection-path callers (rejected_import_evicts..., rejected_import_
  preserves...) PASS.
- builder.rs create_context: local wrapper `context_id_bytes` (builder.rs:704) delegates
  to chokepoint → create-time keying also decodes 64-hex. New test
  create_context_keys_crypto_under_decoded_digest_not_sha256 PASSES.
- Funnel complete: all runtime+FFI keying sites rerouted (governance/class_s/key_destruction/
  ttl/governance_logic/lifecycle/messaging/event_log×3/testing×3/node.rs). Only remaining
  raw `context_id_bytes` non-test calls = chokepoint fallback (state.rs:2088) + builder
  wrapper. routing stays context_routing_id (unchanged, domain-separated).
- scp-protocol context_id_bytes + context_routing_id BODIES unchanged (doc-only).
- clippy -D warnings clean (runtime+protocol). 2312 scp-runtime + 726 scp-testing PASS.
- New intra-doc links resolve (context_id_bytes pub, context_id_to_bytes pub). cargo doc
  errors are ALL pre-existing unrelated (serde_bounded_bytes, validate_ceiling_entry, etc.
  — none in changed files; 82 context_id_to_bytes occurrences produced ZERO doc error).
- NO CI YAML/.sh in diff range (prompt's "removed bash/awk gate" not in origin/main...HEAD —
  must be a prior PR-A revision). Nothing broken in scope.
- No signature changes; no existing test broken.
