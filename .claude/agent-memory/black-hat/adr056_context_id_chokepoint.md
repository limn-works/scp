---
name: adr056-context-id-chokepoint
description: ADR-056 context-id keying chokepoint context_id_to_bytes; recovery-direct double-hash fail-open was REGRESSED then FIXED @295bc3154 — re-audit CLEAN, mutation-proven
metadata:
  type: project
---

# ADR-056 canonical context identity (chokepoint = `context_id_to_bytes`)

A context's canonical identity IS its 32-byte digest; id string = hex(digest). Chokepoint
`crate::context::state::context_id_to_bytes` (state.rs:2072) decodes a 64-lowercase-hex id to its
digest; falls back to raw `scp_protocol::context::context_id_bytes` (SHA-256) only for non-64-hex
synthetic labels. Raw primitive on a real id DOUBLE-HASHES → wrong slot → fail-OPEN.

## HISTORY: recovery-direct regression — FOUND (earlier rev) then FIXED @295bc3154
- `recovery_send_notification_direct` (supervisor.rs:3583) was briefly regressed chokepoint→raw on the
  false rationale "only identity-private-state reaches it." FIX commit 295bc3154 reverted it to the
  chokepoint. Re-audit @295bc3154: CLOSED. Real member ids DO reach this path (revoke_ucans seq1 /
  rotate_key_packages seq2 via dispatch_trust_recovery_direct:3482, no registration gate).

## Re-audit @295bc3154 verdict: NO actionable findings. Reusable conclusions:
- Sole sanctioned production raw-primitive site = chokepoint's own fallback (state.rs:2088). Every other
  raw call is `#[cfg(test)]`-scoped (AST-scope sweep). agent_binding_pipeline_tests.rs = whole-file
  `#[cfg(test)] mod` (mod.rs:445). Tests use `ctx-*` non-hex labels where raw==chokepoint anyway.
- Registered-actor twin recovery_send_notification (trust_recovery_helpers.rs:322) keys identically via
  chokepoint. Only delta = inner.epoch (direct hardcodes 0) but it's signed-PLAINTEXT, NOT AAD-bound
  (AAD epoch = sender-key epoch from real crypto state inside seal); recipient ignores inner.epoch. SOUND.
- seal/open guard (provider.rs:1581/1666): `context_id_to_bytes(ctx_str) == *context_id`. AAD binds RAW
  string (§9.16.1), NOT digest → cross-string opens fail at AEAD = encryption-as-access-control IS the
  backstop. S↔hex(SHA-256(S)) same-slot collision (synthetic label vs its hex) benign — AAD raw-string
  binding blocks any cross-string decrypt; not newly introduced.
- Routing string-derived & unchanged: context_routing_id = SHA-256("scp:context-routing:"||ctx_str),
  paired with keying via same ctx_str. publish_context/delete_published paired on digest. §6.2.4 saga:
  wire digest → hex::encode → lookup(hex) registry key → crypto under context_id_to_bytes(hex)=digest. ✓
- scp-node/scp-relay: NO crypto keying sites. scp-node compute_routing_id = bare SHA-256(id) (no domain
  sep) — pre-existing, routing-only, OUT of ADR-056 scope, not a finding.
- Uppercase 64-hex caller-supplied id → SHA-256 fallback (can't be §6.2.4 target; wire hex always
  lowercase). Availability quirk, internally consistent, no fail-open.
- BOTH regression tests MUTATION-PROVEN (reverted both fixes to raw → both FAIL with exact fail-open
  signature: recovery "CryptoFailed: no MLS group"; builder "MUST be keyed under decoded digest").
  Tests: recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive (supervisor.rs:14124),
  create_context_keys_crypto_under_decoded_digest_not_sha256 (builder.rs:967).

## SOUND (unchanged from prior pass)
- Chokepoint (state.rs:2072): strict 64-lowercase-hex guard; total (no panic; if-let fallthrough).
- builder.rs:704 local wrapper delegates to chokepoint → create path digest-keyed.
- All runtime keying (governance_logic, lifecycle_helpers, messaging_helpers, key_destruction,
  governance handler, ttl.rs wrapper) + all 6 FFI event_log/testing reroutes through chokepoint.
