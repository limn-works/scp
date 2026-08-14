---
name: adr056-context-id-chokepoint
description: ADR-056 context_id_to_bytes chokepoint review (PR-A rev4, 859f1af13) — interim doc mitigation for two same-signature pub fns until #1931 ContextDigest newtype
metadata:
  type: project
---

ADR-056 introduces `context_id_to_bytes(&str)->[u8;32]` in `crates/scp-runtime/src/context/state.rs` as the SINGLE keying chokepoint: DECODES a real 64-hex context id to its digest (canonical id IS the digest, string is hex(digest)), falls back to raw `scp_protocol::context::context_id_bytes` (pure SHA-256) for synthetic/non-64-hex labels.

**Why:** Pre-fix runtime did `SHA-256(hex(digest))` = double-hash, so §6.2.4 cross-context saga compared wire raw-digest against double-hashed state.context_id and never matched — uncommittable in prod, masked by non-hex test fixtures.

**Review verdict (rev4):** APPROVED. Doc mitigation coherent. Both the raw-primitive primary doc AND the `context_routing_id` cross-ref doc corrected (no residual "All modules MUST use this function" contradiction). All 10 FFI/test-harness + node.rs + ~12 runtime-internal keying sites consistently route through the chokepoint with identical ADR-056 comments. supervisor.rs:3547 deliberately uses raw primitive (byte-identical for "identity-private-state", documents synthetic-case intent); supervisor.rs:12670 is test-only fixture (non-64-hex ctx- ids).

**Discoverability gap (observation, not blocking):** wrong sibling `scp_core::context::context_id_bytes` (raw primitive) sits at the SHALLOW path via glob `pub use scp_protocol::context::*` in scp-core/src/lib.rs:53. Correct resolver only reachable at deeper `scp_core::context::state::context_id_to_bytes` (lib.rs:91). No name collision blocks a cheap shallow re-export — but #1931 ContextDigest newtype makes raw-primitive keying a compile error, which subsumes it. Recommended deferring shallow re-export to #1931 rather than adding interim surface.

**How to apply:** When #1931 lands, verify the ContextDigest newtype actually makes the raw primitive unreachable from keying sites (only the chokepoint can mint it) and that the interim doc-only CRITICAL warnings can be deleted. The source-text grep gate was already (correctly) removed as non-convergent — don't let anyone re-add it.
