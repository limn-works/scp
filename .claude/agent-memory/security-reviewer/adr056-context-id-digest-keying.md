---
name: adr056-context-id-digest-keying
description: ADR-056 canonical context-id = 32-byte digest; context_id_to_bytes chokepoint; PR-A review (branch feat/123, HEAD 8de31a106)
metadata:
  type: project
---

# ADR-056 Canonical Context-ID Digest Keying (PR #123 / #1924)

**Why:** Runtime double-hashed real context ids: `state.context_id = SHA-256(handle.id)` but `handle.id` is already `hex(digest)`, so MLS group / sender keys / event log keyed under `SHA-256(hex(digest))` while §6.2.4 saga compares the raw digest. Coincided only in non-hex fixtures; real `generate_context_id` ids make §6.2.4 uncommittable + event-log queries fail-open (empty absence proofs).

**How to apply (recurring class):** Any context-id→keying-bytes resolution MUST funnel through `scp_runtime::context::state::context_id_to_bytes` (now `pub`, reachable as `scp_core::context::state::context_id_to_bytes`). It decodes 64-char-lowercase-hex → digest, else falls back to raw `context_id_bytes` (SHA-256) for synthetic labels. Raw `scp_protocol::context::context_id_bytes` is routing/synthetic-ONLY.

## Review verdict (HEAD 8de31a106)
- Core chokepoint SOUND: strict 64-lowercase-hex guard, total/no-panic, non-64-hex byte-identical to old behavior. Two allowlisted production raw sites: state.rs:2088 (resolver fallback) + supervisor.rs:3547 (synthetic identity-private-state). MLS seal/open consistency guards symmetric. No production keying path outside runtime/ffi double-hashes a real ctx (scp-node/transport/identity/media clean; WASM keys by STRING via require_context, structurally immune per ADR-034).
- Gate `scripts/check-context-id-keying.sh`: lexer hardening VERIFIED sound via adversarial probes — raw call + trailing `//#[cfg(test)]` comment = DENY; string `{{{` in test mod = DENY following prod; raw call + `"#[cfg(test)]"` string literal = DENY. is_raw on original line, structural decisions on comment/literal-stripped view + leading-token cfg arming. Self-test + real-tree both pass.

## FINDING (LOW, latent) — harness FFI testing.rs siblings not rerouted
- This PR rerouted `scp-testing/src/fullstack/node.rs::add_member` to the digest "because the harness keys real contexts too", and widened gate scan scope to `crates/scp-testing/src`. BUT the sibling harness FFI bridge sites still call raw `context_id_bytes(&context_id)`:
  - `crates/scp-ffi/src/testing.rs` :241 join_from_welcome, :271 sync_sender_keys, :366 decrypt_message
  - `crates/scp-ffi/napi/src/testing.rs` :248, :277, :382 (mirror)
- These are whole-file-EXEMPTED by the gate (`[[ basename == testing.rs ]] && continue`, line 237). Internally inconsistent with the PR's own scope-widen rationale: node.rs (scanned, rerouted) vs testing.rs (exempt, not rerouted) have the identical real-context keying pattern.
- NOT live today: existing Python E2E tests (test_e2e_fullstack.py) use non-64-hex ids ("py-ctx-alice-bob"), so resolver==raw byte-identical. Latent: first real 64-hex id passed to fullstack_create_context → creator/add_member key under digest, join/sync/decrypt under SHA-256(id) → silent cross-slot divergence (decrypt fails / keys land in wrong slot).
- Test-only (feature `allow_in_memory_custody`, never in prod builds) → LOW severity. Recommend rerouting the 6 sites to `context_id_to_bytes` + dropping the `testing.rs` whole-file exemption (rely on the brace-depth #[cfg(test)] tracker, which already exempts genuine test modules).

## `pub` promotion is safe
- context_id_to_bytes pub(crate)→pub grants NO new capability: keying bytes = slot label, not access control. Raw primitive already pub. Resolver only steers to correct slot.
