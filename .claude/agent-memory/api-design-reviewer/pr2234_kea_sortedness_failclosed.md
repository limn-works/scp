---
name: pr2234-kea-sortedness-failclosed
description: PR #2234 @432691d70 review pass 1 — broadcast KEA leaf sortedness + fail-closed error contract; NEEDS REVISION with 3 HIGH findings
metadata:
  type: project
---

PR #2234 (`fix/rotate-content-keys-review-followup`, final commit `432691d70`) — API review pass 1 verdict **NEEDS REVISION**.

**Why:** the PR makes per-author `KeyEpochAdvance` (KEA) event-log emission (a) deterministically ordered and (b) fail-closed on convergent governance triggers. Both changes alter contracts that are only expressed in rustdoc, not in types or the spec.

Three HIGH findings:
1. **Sortedness is doc-only.** `BroadcastContext::rotate_all_author_keys -> Vec<BroadcastKeyEpochAdvance>`, `GovernanceBanResult.rotated_authors`, `UnsubscribeResult.key_rotations` are each sorted by three separate `sort_unstable_by` calls. Root cause is `BroadcastContext.authors: HashMap<String, AuthorState>` (also `BroadcastContextSnapshot.authors`, pub `BroadcastContextClassCParts.authors`). `BTreeMap` makes it sound by construction, deletes all three sorts, and also determinizes snapshot serde byte order. Public sibling `author_dids()` still returns unordered.
2. **`EventLogFailed` promoted to a reachable governance-path error** with no rustdoc `# Errors` on `execute_revoke` / `execute_rotate_content_keys`, no canonical `SCP-CTX-NNNN` code (falls into the generic `SCP-CTX-2001` catch-all in every bridge — `git grep EventLogFailed crates/scp-ffi/` returns nothing), and undefined partial-progress semantics (keys already rotated + N of M leaves durable; a retry double-rotates).
3. **Ascending-`author_did` KEA emission order is normative for §9.9.3** cross-implementation Merkle convergence but lives only in Rust doc comments. The §5.14.8 paragraph this PR added omits it, so the wasm/browser client has nothing to conform to; divergent order reads as equivocation.

Also: the four KEA-emit sites now justify their fail-closed-vs-best-effort choice on **two different axes** — ADR-011 convergence (block path, correct) vs §5.14.8 authorization-direction/coalescing (unsubscribe path, wrong axis for a *leaf* decision). No mechanical rule exists for a fifth site.

**How to apply:** on any follow-up touching broadcast KEA emission, checkpoint counters, or the `ContextError::EventLogFailed` surface, re-check these five. Related: [[cross-sdk-shape-parity]] (error-code parity across bindings), [[eventlog_substrate_phase2_final]] (event-log provider trait).
