---
name: adr056-context-id-keying-chokepoint
description: PR-A (ADR-056 #1924/#1931) context-id digest chokepoint review — all prod keying paths verified routed; one LOW residual (no mechanical guard until ContextDigest newtype #1931)
metadata:
  type: project
---

# ADR-056 context-id-keying chokepoint (PR-A, commit 859f1af13)

Reviewed at /tmp/scp-prA-bh4. **No actionable HIGH/CRITICAL.** Change is sound.

**Why:** A context's canonical identity IS its 32-byte digest; id string = hex(digest)
(generate_context_id = 32 CSPRNG bytes → lowercase hex → exactly 64 chars, verified
context_id.rs:50). Raw primitive `scp_protocol::context::context_id_bytes` = SHA-256(str).
Using it on a real 64-hex id DOUBLE-HASHES (SHA-256(hex(digest)) != digest) → wrong slot →
fail-OPEN. Chokepoint `crate::context::state::context_id_to_bytes` (state.rs:2072) DECODES a
64-char-all-lowercase-hex id to its digest, falls back to raw SHA-256 only for synthetic
labels (identity-private-state, standing-<hex>, ctx-* test ids).

**How to apply (verified facts):**
- Chokepoint decode guard `len()==64 && all (0-9a-f)` exactly matches hex lowercase alphabet →
  decode+try_from always succeed for guard-passing input; `if let && let` fallthrough = TOTAL,
  no panic/unwrap. Decode is a BIJECTION 64-lc-hex-string ↔ 32B digest → two distinct id
  strings can NEVER collide to one digest slot → no cross-context confusion.
- ALL production keying routed through chokepoint: builder.rs:766 (create), messaging_helpers
  (send/deliver/envelope/snapshot/timeout/buffer), lifecycle_helpers (export/import/restore),
  key_destruction, ttl, governance_logic, class_s, mls/provider.rs open-side resolve-consistency
  guard (binds cleartext ctx-str to keyed digest), supervisor.rs:9038. ALL FFI bridges (PyO3/
  NAPI/UniFFI event_log + 6 testing.rs reroutes) + scp-testing node.rs add_member.
- create-vs-join split CLOSED for real 64-hex id: creator create_context→builder→chokepoint
  (digest); joiner add_member/join_from_welcome/sync_sender_keys/decrypt→chokepoint (digest).
  state.context_id is the STRING (=hex(digest)); §6.2.4 saga hex-encodes wire digest back to
  the string for registry lookup (supervisor.rs:5490) → consistent.
- LEGITIMATE raw-primitive prod calls (correct, byte-identical): supervisor.rs:3547
  (identity-private-state, fixed 22-char literal, never 64-hex→hashes); mod.rs:130
  (context_routing_id internal). scp-node compute_routing_id (projection.rs) = routing key by
  design, never crypto-keys. WASM keys contexts:HashMap<String,_> by id STRING (no digest
  conversion) → no double-hash class there. relay = dumb pipe, no keying.

## LOW (residual, accepted/deferred to #1931) — no mechanical guard on miswiring
Raw primitive stays `pub` (needed for routing/synthetic). The removed grep gate was net-new in
THIS PR (unsound Rust pseudo-lexer: lifetimes/block-comments/multiline-strings corrupt cfg(test)
brace tracking — 3 review rounds each surfaced a new fail-open) → dropped per #1826 precedent +
non-convergent-enforcement guard. Replacement = chokepoint (1 source of truth) + 1
mutation-resistant digest-keying unit test (builder.rs create_context_keys_crypto_under_decoded
_digest_not_sha256) + state.rs chokepoint unit tests. RESIDUAL GAP: that test only pins the
CREATE path. The fullstack e2e integration tests all use SYNTHETIC non-64-hex ids
("e2e-encrypted-ctx") where raw==chokepoint, so they'd NOT catch a NEW keying site wired to the
raw primitive (double-hash ships silently if its own e2e uses a synthetic id). Exactly the class
ContextDigest newtype (#1931) closes by construction. Correct to defer; flag, not a blocker.
