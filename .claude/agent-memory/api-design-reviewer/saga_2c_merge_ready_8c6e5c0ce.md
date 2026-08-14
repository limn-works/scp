---
name: saga-2c-merge-ready-8c6e5c0ce
description: Saga-2c final merge-readiness pass at HEAD 8c6e5c0ce — APPROVED/ship; the +1 over 54f937e0f is a PyScp::resume doc-comment-only fix
metadata:
  type: project
---

Saga-2c worktree, HEAD `8c6e5c0ce` — API merge-readiness confirmation. APPROVED / ship.

The only delta over the previously-reviewed `54f937e0f` (see [[saga_2c_final_pass_54f937e0f]]) is one doc-comment-only commit `8c6e5c0ce`: rewrites `PyScp::resume` doc in `crates/scp-ffi/src/scp.rs` (lines ~247-256). Removed a STALE/WRONG claim ("caller must re-establish the relay connection explicitly — resume does not reconnect automatically") and replaced it with the true behavior: resume clears the suspended flag, then the `BridgeInstanceCore::resume` trait default body (bridge_instance.rs:2544-2547) runs `reconnect_transport_if_pending().await?` then `restore_all_persisted_contexts().await`. Verified the trait body and that the new doc now matches the NAPI wrapper doc (napi/src/scp.rs:300-304). UniFFI doc is briefer but not contradictory.

**Why:** This was the last doc/behavior inconsistency on the public resume surface; it's now resolved. No signature change, zero source-logic change.

**How to apply:** The feature's typed public surface (RestoredContexts witness, restore_on_startup/restore_all_contexts pub(crate), with_providers_and_journal, §5.14.13 hosting-handshake *Fields types) is UNCHANGED from 15c1aef9c/54f937e0f and remains APPROVED. No merge-blocking API issue at HEAD. Working tree had only agent-memory edits (other reviewers), no source.
