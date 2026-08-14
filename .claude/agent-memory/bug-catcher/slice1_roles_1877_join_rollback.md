---
name: slice1-roles-1877-join-rollback
description: WASM join_context_encrypted F1 rollback leaves an orphan MemberJoined Merkle leaf (append-only log) on welcome failure — diverges from native ordering; rollback only strips in-memory membership.
metadata:
  type: project
---

Branch wasm/1877-slice1-adopt-context-role-state, HEAD 530752ac5, crates/scp-ffi/wasm/src/manager.rs.

**Finding (MEDIUM):** `join_context_encrypted` (~2249) calls inner `join_context` FIRST, which appends a `MemberJoined` leaf to the durable append-only Merkle event log (`append_log_event` ~606, unconditional — failure only console-logged) AND pushes a `MemberJoined` buffer event. THEN `join_from_welcome` (crypto) runs. On crypto failure the F1 inline-strip rolls back in-memory membership (members/assignments/member_capabilities/suspensions/member_sequence_numbers) but CANNOT remove the Merkle leaf (no truncation API by design) and does NOT drain the `MemberJoined` buffer event.

Native (scp-runtime lifecycle_helpers.rs join_context ~666) orders the opposite: Phase 1-3 MLS → Phase 4 membership (rolls back MLS on failure) → Phase 5 `append_context_event("MemberJoined")` LAST, only after crypto+membership succeed. So native never appends a MemberJoined leaf on welcome failure. → cross-platform Merkle-root divergence on the failure path; same equivocation class as finding_runtime_eventlog_not_rfc6962. The F1 test asserts membership/sequence rollback only (non-vacuous for those) but does NOT assert event_log_leaf_count, so it doesn't catch the orphan leaf.

Root cause: ordering — append-then-crypto in WASM vs crypto-then-append in native. Local fix: defer the MemberJoined event/log append until after join_from_welcome succeeds (split join_context, or move append into join_context_encrypted post-crypto).

**F2 TransferAdmin (~3995-4030): CLEAN.** prior-role capture before mutation, restore guarded on membership, creator_did mutated last (so issuer correct throughout), no panic. Unreachable today (built-in roles infallible) — defense-in-depth.

**F1 re-borrow:** require_active_context_mut after inner join — `?` would skip strip if non-active, but join_from_welcome doesn't touch self.contexts in single-threaded WASM, so not reachable. Defensive only.
