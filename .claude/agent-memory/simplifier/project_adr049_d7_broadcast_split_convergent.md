---
name: adr049-d7-broadcast-split-convergent
description: ADR-049 D7 try_broadcast_commit/apply_broadcast_failure split is a forced, minimal fix — NOT over-engineering/BLOCKER; the async-send-vs-sync-apply pattern recurs across D7 transport helpers.
metadata:
  type: project
---

Splitting `try_broadcast_commit_or_enqueue` into async `try_broadcast_commit` (send-only, returns `Option<BroadcastFailure>`) + sync `apply_broadcast_failure` (bookkeeping) is CONVERGENT and minimal, NOT a BLOCKER.

**Why:** ADR-049 Decision 7 made `ContextTransportProvider` async. The async send cannot be awaited inside the sync `commit_class_s_keep` closure, so the fail-closed bookkeeping (`commit_fault` safety gate + `pending_commits` retry) got hoisted onto a coalesced Class-C view — a crash-window loses the gate → silent MLS group desync. The split lets the caller pick durability: 3 safety-gated Class-S sites (execute_remove_member, execute_rotate_content_keys, leave_context) re-persist the failure inside a SECOND `commit_class_s_keep`; 2 best-effort sites (add_member, reset_member) stay coalesced. `Option<Failure>` between an async producer and a sync applier is the idiomatic minimal factoring — no simpler equivalent exists given the constraint.

**How to apply:** This async-send-outside-closure / sync-apply-inside-closure shape is inherent to every D7 async transport helper that must preserve fail-closed durability (sibling helpers: encrypt_and_send, drain_and_deliver_sender_keys). Don't flag it as complexity. The only real cleanup: the 3 fail-closed sites duplicate an identical ~15-line `commit_class_s_keep`/`CommitBroadcastBorrows{...rest_mut()...}` wrapper — extractable into one `keep_broadcast_failure(cell: &mut ClassSCell, deps, ctx, failure)` helper (modest REPETITION, not blocking). `BroadcastFailure{pending,label,error}` fields are load-bearing; label/error are derivable from pending but carrying them avoids coupling to the "last_error always Some" invariant — leave as-is.
