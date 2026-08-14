---
name: adr056-recovery-chokepoint-reroute
description: ADR-056 recovery-direct chokepoint reroute review (3a9d7d91d / PR-A #123 #1924) — APPROVED; mls open-guard fix, stale comment leftover in trust_recovery_helpers
metadata:
  type: project
---

ADR-056 keying chokepoint, HEAD `3a9d7d91d` (PR-A, #123 / #1924). Builds on [[adr056_context_id_keying_chokepoint]].

**Verdict: APPROVED.** The recovery-regression fix is clean and mutation-resistant.

**What this commit does:** reroutes `recovery_send_notification_direct` (supervisor.rs) from the raw primitive `scp_protocol::context::context_id_bytes` to the chokepoint `crate::context::state::context_id_to_bytes`. The earlier "only synthetic identity-private-state reaches here" comment was false — `revoke_ucans`/`rotate_key_packages` dispatch recovery notifications to real 64-hex member contexts with no live actor; raw primitive double-hashed → notification keyed a slot no member listens on → compromise-recovery fail-open. Now the sole production raw-primitive caller is the resolver's own fallback (state.rs:2088). Verified by grep: all other raw-primitive calls are `#[cfg(test)]`.

**Consistency verified:** every keying site routes through chokepoint — FFI ×10 (event_log/testing/bridge via `scp_core::context::state::context_id_to_bytes`), runtime helpers (messaging/lifecycle/key_destruction/governance_logic/ttl/builder), node.rs, mls/provider.rs.

**Substantive fix found in mls/provider.rs (not just keying alignment):** the `open` AAD-binding consistency guard previously compared `context_id_bytes(ctx_str) != *context_id` — for a real 64-hex id this NEVER matched (digest vs SHA-256(hex(digest))), so `open` would reject every real-context message. Rerouted through chokepoint. Test renamed `open_rejects_context_id_str_that_does_not_resolve_to_context_id`.

**Findings:**
- LOW: `trust_recovery_helpers.rs:350` comment still says "the raw context_id_bytes used for MLS crypto keying" — but line 322 binds it via the chokepoint (the digest, not raw). This is the registered-actor handler the commit says it "matches"; supervisor.rs fixed its twin of this exact stale comment but missed this one. Same comment-induced misdirection class the ADR's double-hash-trap warns about.
- OBS (discoverability, recommend not block): `scp_core/src/lib.rs:53` `pub use scp_protocol::context::*` glob re-exports the WRONG sibling `context_id_bytes` at shallow `scp_core::context::context_id_bytes`; correct chokepoint sits deeper at `scp_core::context::state::context_id_to_bytes`. node.rs change in THIS diff was literally fixing a caller burned by exactly that shallow-path autocomplete. The just-found recovery regression is the 2nd instance of the same-signature trap firing → argues for doing the shallow re-export hardening (or #1931 ContextDigest newtype) sooner, not deferring. Two delegating local wrappers (builder.rs:704 `context_id_bytes`, ttl.rs:71 `context_id_to_bytes`) add same-name collisions but are thin/correct/documented.

#1931 ContextDigest newtype = permanent fix (raw-primitive keying call becomes compile error).
