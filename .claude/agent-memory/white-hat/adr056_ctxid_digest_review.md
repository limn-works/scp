---
name: adr056-ctxid-digest-review
description: ADR-056 canonical-context-id=digest defense review — chokepoint + seal/open guards SOUND, coverage adequate, ship; grep-gate removal correct
metadata:
  type: project
---

# ADR-056 canonical-context-id-as-digest — defense review (2026-06-29, branch ctxid-digest @04f24646e)

**Verdict: construction sound, coverage adequate, SHIP. Zero must-fix.**

## The invariant
A context's canonical identity IS its 32-byte digest; the id STRING is `hex(digest)`.
Resolution = DECODE not re-hash. Bug #1924: runtime did `SHA-256(hex(digest))` = double-hash,
keying a phantom slot. Caught only by non-hex `ctx-*` fixtures masking divergence.

## Two-domain rule (load-bearing, easy to conflate)
- **Keying** (MLS group / sender keys / event log): `context_id_to_bytes` (state.rs:2072) — strict 64-lowercase-hex → `hex::decode`, else `SHA-256(id)` fallback. Single chokepoint.
- **Routing** (relay slots): string-keyed SHA-256. `context_routing_id`=domain-sep; `broadcast_routing_id`=raw SHA-256(string). Read side `projection::compute_routing_id`=SHA-256(lowercase(id)). Routing MUST NOT follow keying digest.

## Enforcement (verified by construction)
- Chokepoint is single source of truth: ZERO raw-primitive keying calls in production across runtime context/* AND all 4 FFI bridges (grep-confirmed). Remaining raw calls are #[cfg(test)] using `ctx-*`/TEST_CTX_STR (coincide) + chokepoint fallback + broadcast_routing_id.
- Seal/open guards (provider.rs:1581 seal, :1675 open): fail-closed `context_id_to_bytes(str)!=*ctx_id` ⇒ CryptoFailed, BEFORE any crypto. Independent 2nd layer for caller mismatch (not chokepoint-internal defect — that's the chokepoint's own unit tests).
- builder.rs:704 local `context_id_bytes` SHADOW delegates to chokepoint (deliberate, doc'd).

## Detection — every ADR-named path has real-64-hex mutation-resistant test
- canonical_context_id_tests x6 (state.rs:2253)
- create_context_keys_crypto_under_decoded_digest_not_sha256 (builder.rs:966)
- seal/open_rejects_context_id_str_that_does_not_resolve (provider.rs:4583/4539) — exact error string, fires before crypto
- destroy_ephemeral_keys_real_context_via_chokepoint (key_destruction.rs) + ttl_expiry variant (ttl.rs) — FORWARD-SECRECY, highest value (silent fail-open if regressed: live group survives destruction)
- recovery_direct_keys_real_context_via_chokepoint (supervisor.rs:14093) — TransportFailed(digest seal ok) vs CryptoFailed(regressed)
- broadcast_publish_routes_under_sha256_routing_id_not_keying_digest (broadcast_helpers.rs:902)

## Three fixes in this branch (all sound, all tested)
1. recovery_send_notification_direct: raw→chokepoint. Reached for ANY unregistered ctx (revoke_ucans/rotate_key_packages dispatch real 64-hex ids, no registration gate), not just synthetic identity-private-state. epoch-0 hardcode SAFE: AAD binds SENDER-KEY epoch (encrypt.rs:129, from live state via provider.rs:1602), NOT inner.epoch plaintext field. VERIFIED.
2. broadcast publish routing: was keying-digest, broke on chokepoint change → host_site CommitCountMismatch (zero-asset deploy). Fixed to broadcast_routing_id. Publish slot now == projection read slot by construction.
3. FFI event-log(4) + test-harness(6) sites: raw→chokepoint.

## Grep-gate removal = CORRECT
Regex can't soundly track #[cfg(test)] in Rust (lifetime/char-literal, block-comment braces, multiline strings) — non-convergent denylist. Replaced by ContextDigest newtype (#1931, compile-time, closed positive type). Matches #1826/OwnedIdentityDid precedent. Do NOT reintroduce any source-text gate as stopgap.

## Residual (acceptable until #1931)
Only gap = a future NEW keying site calling raw primitive directly. Bounded by convention+doc-contract+obvious-pub-chokepoint. #1931 newtype makes it a compile error.

## Optional P2 hardening (defense-in-depth, NOT required)
Pin the cross-module epoch-0 safety assumption: test in sender_keys::encrypt asserting AAD is pure fn of (ctx,did,epoch,seq) ARGS only (no envelope field). Recovery-direct safety silently regresses if build_sender_aad ever binds an envelope-supplied epoch.
