---
name: pr-adr056-context-id-keying-chokepoint
description: ADR-056 (#1924/#1931) context-id digest chokepoint review — fixes double-hash fail-open; verified CLEAN, no remaining raw-primitive prod keying path
metadata:
  type: project
---

# ADR-056 context-id keying chokepoint (commit 859f1af13, branch fuzz-pin-nightly worktree)

**Verdict: CLEAN. No actionable findings.** Reviewed exhaustively, build + all chokepoint tests pass.

## What it fixes
Pre-ADR-056, `PerContextState.context_id` and all crypto/event-log keying derived bytes via the
raw `scp_protocol::context::context_id_bytes` = `SHA-256(id_string)`. For a REAL context id
(`hex(digest)` from `generate_context_id`, 64-lowercase-hex CSPRNG) this DOUBLE-HASHES the digest →
wrong slot. The §6.2.4 cross-context tool saga compares wire `target_context_id` (raw 32-byte
digest) against `state.context_id` at saga.rs:1034 (`SCP-SAGA-13014` binding) — pre-fix that never
matched a real digest. Fix routes ALL keying through single chokepoint
`crate::context::state::context_id_to_bytes` (state.rs:2072, now `pub`): 64-lowercase-hex →
`hex::decode` to digest; else raw `SHA-256` fallback (byte-identical to before for synthetic labels).

## Why it's sound (verified)
- Guard `len==64 && all [0-9a-f]` → `hex::decode` always yields 32B, `try_from` can't fail, total
  fallback unreachable-but-safe (no panic/unwrap). 6 unit tests pass (decode-not-rehash, synthetic
  fallback, standing-prefix, uppercase-guard, near-64-len). End-to-end `create_context` keying test
  (builder.rs:967) drives real MLS provider, asserts group keyed under decoded digest — mutation-resistant.
- `generate_context_id` (scp-ffi/common/context_id.rs:50) = `hex::encode(32 CSPRNG bytes)` = exactly
  64-lowercase-hex → matches guard exactly. Round-trip closed: digest→`hex::encode`(lowercase)→decode→digest.
  Saga `hex_context_id`=`hex::encode` (saga.rs:140) = lowercase, so target_hex re-lookup round-trips.
- Every real prod keying site routes through chokepoint: builder.rs:766 (local `fn context_id_bytes`
  SHADOW at :704 delegates to chokepoint — confusing but correct), lifecycle_helpers create/import/
  restore (state.context_id = chokepoint result, feeds saga binding), messaging_helpers send/deliver/
  snapshot, key_destruction (fail-open close was the worst pre-fix: destroy_mls_group would no-op +
  report KeysDestroyed while group survived), ttl.rs (local wrapper now → chokepoint), governance_logic
  event-log, class_s, supervisor:9049 publish_context, recovery.rs `identity-private-state`. All 4 FFI
  event_log + 6 FFI testing.rs + scp-testing node.rs rerouted.
- Legit raw-primitive uses remain: `broadcast_routing_id` (protocol mod.rs:130, spec §5.14 raw hash),
  `context_routing_id` (domain-separated), supervisor.rs:3547 (`identity-private-state` synthetic,
  byte-identical to chokepoint fallback), all `#[cfg(test)]` fixtures. Standing ids use PREFIXED form
  (`"standing-"+hex`, 73 chars → hashes; raw-digest-hex is a SEPARATE saga-gating reservation key, not
  crypto keying — no divergence). No bare-64-lowercase-hex synthetic label exists in any prod path.
- WASM (4th FFI) has no Supervisor/MLS keying path (ADR-034) — chokepoint is native-only; bridge.rs:374
  SHA256 is bridge_id composite, not context keying.

## Gate removal is legitimate
`scripts/check-context-id-keying.sh` (343→629 lines, grep/awk) was NET-NEW on this branch
(ea592648f), removed in HEAD with its 15 CI workflow lines. Never lived on main → not weakening an
existing enforcement file. A regex can't soundly tokenize Rust `#[cfg(test)]` scope; same precedent as
OwnedIdentityDid gate-drop (CI gate ≈ zero marginal security vs insider who edits the gate). Planned
`ContextDigest` newtype (#1931) is the convergent compiler-enforced mechanism.
