---
name: adr056-canonical-context-id-digest
description: ADR-056 context_id_to_bytes chokepoint review — fail-open class, the two break patterns, residual enforcement gap (#1931 ContextDigest newtype not built)
metadata:
  type: project
---

# ADR-056 canonical-context-id-as-digest (PR-A #123, branch ctxid-digest)

**The change:** `context_id_to_bytes` (state.rs:2071) is the SINGLE keying chokepoint.
- Real id = exactly 64 chars AND all `0-9a-f` (byte-level: `is_ascii_digit() || (b'a'..=b'f')`)
  → `hex::decode` to the 32-byte digest (the canonical identity per §6.2.4:276).
- Else (synthetic `identity-private-state`, `standing-<hex>`, `ctx-…`, uppercase, 63/65-len)
  → raw `scp_protocol::context::context_id_bytes` = `SHA-256(id)` (byte-identical to pre-change).
- Guard is EXACT: lowercase-only (uppercase routes to hash deliberately), length-exact, ASCII-only
  (no Unicode/whitespace bypass). `generate_context_id` (scp-ffi/common/context_id.rs:50) always
  emits 64-lowercase-hex via `hex::encode([0u8;32])` → invariant matches guard exactly.

## TWO fail-open break patterns (memorize — future PRs will reintroduce)
Before this change `state.context_id == SHA-256(id) == context_id_bytes(id)` (latent equality).
The digest path broke it: for a real id `decode(id)=digest ≠ SHA-256(id)`.
1. **KEYING site calling raw primitive** = double-hash `SHA-256(hex(digest))`, keys a slot
   nobody listens on. Silent. (recovery-direct supervisor.rs:3583 fix 295bc3154; key_destruction.rs
   destroy would no-op while group SURVIVES; all event-log/MLS/snapshot sites.)
2. **ROUTING slot calling the chokepoint** = stores blob at digest-slot, but reader computes
   `SHA-256(id)`/`broadcast_routing_id`/`context_routing_id`. (broadcast publish broadcast_helpers.rs:363
   fix a969122b6 → host_site CommitCountMismatch{committed:0}.)
Rule: relay routing slots (transport send_message/publish_context) MUST use `context_routing_id`
(domain-sep) or `broadcast_routing_id` (SHA-256, §5.14.6); crypto/event-log keying MUST use the chokepoint.

## Why the crypto contract survives the bytes change (ROBUST)
MLS `seal`/`open` (provider.rs:1558/1842) bind the RAW context_id STRING into AEAD AAD
(`ctx_str = inner.context_id`, §9.16.1), NOT any 32-byte derivation. The `context_id_to_bytes(ctx_str)
!= *context_id` check is only defense-in-depth consistency. So native↔WASM interop is string-based and
unaffected by the derivation change. WASM (ADR-034, no Supervisor) bridge.rs SHA-256 is a bridge_id, not
MLS keying. compute_routing_id (scp-node projection.rs:79) = lowercase+SHA-256, matches broadcast publish.

## VERDICT: could NOT break it. All keying sites route through chokepoint; all routing sites use routing
primitives. Every non-test raw-primitive call is the chokepoint's own fallback (state.rs:2088) or test
fixtures (export_import test ids are `ctx-…` non-64-hex → hash identical either way). governance_helpers
imports `context_id_to_bytes` from state (already correct pre-PR). FFI bridges (PyO3/NAPI/UniFFI) +
fullstack node all chokepoint. 6 regression guards pass; scp-runtime compiles clean.

## RESIDUAL RISK (threat-model, not a diff bug)
- Grep gate `check-context-id-keying.sh` DELETED (da017d9f0 #1931) — was unsound (regex can't lex Rust
  cfg(test) brace depth; lifetimes/block-comments/multiline-strings each a fail-open).
- The claimed sound replacement, the **`ContextDigest` newtype, DOES NOT EXIST** — tracked as future #1931.
  `grep struct ContextDigest` = 0 hits. So RIGHT NOW the ONLY protection against a new keying site calling
  the raw primitive is: (a) one chokepoint exists, (b) per-site mutation-tests — which ONLY cover the 3
  already-found sites. A future PR adding a keying site can reintroduce either fail-open silently with
  nothing mechanical catching it until #1931 lands the newtype. Recommend #1931 be treated as load-bearing.
