---
name: adr056-chokepoint-rev5
description: ADR-056 context_id_to_bytes keying chokepoint (rev5, 9b6ed3039) — APPROVED; doc-fix coherent, 10 FFI sites route identically, re-export depth asymmetry is the one non-blocking rec
metadata:
  type: project
---

ADR-056 keying chokepoint review at commit 9b6ed3039 (read-only worktree /tmp/scp-prA-rev5). APPROVED.

This is a later revision of the same change tracked in [[adr056_context_id_keying_chokepoint]] (that earlier note was commit 859f1af13). What changed by rev5:
- `context_id_to_bytes` promoted `pub(crate)`→`pub`, given full chokepoint doc; strict 64-lowercase-hex guard → `hex::decode` to digest, else fall through to raw `scp_protocol::context::context_id_bytes` SHA-256. Total function (no panic/unwrap).
- BOTH the primary doc on the raw primitive AND the previously-contradicting cross-ref in `context_routing_id`'s doc (scp-protocol/src/context/mod.rs) were corrected — no residual contradiction anywhere (grepped rust + .docs).
- New mutation-resistant test `create_context_keys_crypto_under_decoded_digest_not_sha256` (builder.rs): asserts crypto keyed under decoded digest AND empty under SHA-256(id), with a precondition that the two differ. Plus `canonical_context_id_tests` in state.rs pinning decode/hash branching (incl. uppercase-64hex hashes, 63/65 lengths hash).

Consistency verified: all 4 FFI event-log sites (pyo3 event_log.rs, napi event_log.rs ×2, uniffi bridge.rs) + 6 test-harness sites (pyo3 testing.rs ×3, napi testing.rs ×3) + scp-testing node.rs route through `scp_core::context::state::context_id_to_bytes` — one canonical pattern, identical comment, no drift. builder.rs production create path delegates via local shadow fn → chokepoint. Only production raw-primitive call left is supervisor.rs:3547 (`"identity-private-state"` synthetic, correctly documented). All other raw-primitive call sites are `#[cfg(test)]` fixtures (ctx-* labels) — legitimately on the hash fallback.

Re-export depth asymmetry (the one standing observation, non-blocking, same as prior note): scp-core/src/lib.rs:53 `pub use scp_protocol::context::*` puts the WRONG sibling `context_id_bytes` at the SHALLOW `scp_core::context::context_id_bytes`; the SAFE chokepoint sits one level deeper at `scp_core::context::state::context_id_to_bytes` (line 91). Autocomplete surfaces the trap first. Cheap fix = add `pub use scp_runtime::context::state::context_id_to_bytes;` shallow re-export now. #1931 ContextDigest newtype is the permanent compile-enforced fix.

Re-confirmed on a fresh independent pass (same commit). Two extra production-looking raw-primitive sites checked and cleared: supervisor.rs:12670 (test-snapshot helper, under `mod tests`) and mls/provider.rs:4273/4848 (under `mod tests`). Also confirmed the protocol-side `context_id_to_bytes` mention is a bare CODE SPAN not an intra-doc link — correct, because scp-protocol has zero dep on scp-runtime/scp-core (verified Cargo.toml; a link would be circular). The `broadcast_routing_id` doc legitimately keeps its `context_id_bytes` reference (broadcast routing IS the raw hash, §5.14) — not a contradiction.

Verdict: APPROVED. The chokepoint is a real behavioral fix (decode-not-rehash for #1924's §6.2.4 double-hash), not merely doc; coherent and sufficient until #1931.
