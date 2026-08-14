---
name: adr049-2g-placeholder-deletion
description: ADR-049 Phase 2G — deleting dead actor-mailbox Placeholder variants; sound, but skeleton-dispatch is the un-retired parallel scaffold with the same expired premise
metadata:
  type: project
---

Branch `chore/2g-delete-placeholder-variants` @28b2c5f47. Deleted 8 dead
`*Command::Placeholder` variants + their `reply_not_implemented` handlers +
supervisor arms; migrated tests onto real commands (`QueriesCommand::MemberCount`
via `smoke_query`; `MessagingCommand::DrainEvents` for 2 poison-recovery tests).

**Verdict: decisions SOUND.**
- Placeholder was explicit commit-6 compile-stability scaffolding ("deleted in
  commit 12 with the shim"). Premise expired: every handler now routes through
  `dispatch_state` to real handlers. No downstream step needs it as an extension
  point — the one not-yet-wired surface (single-context-async standing-pair
  creation) lives on the `standing_context` get-or-create path, NOT a mailbox
  Placeholder (DEFERRED-commit-11 doc confirms). Reserving enum variants as
  "future extension points" is a Rust non-idiom.
- `MemberCount`/`DrainEvents` are PRINCIPLED substitutes. MemberCount is a pure
  read (`Outcome{mutated:false}` by construction) — preserves the placeholder's
  no-op property in plumbing tests, and STRENGTHENS `actor_with_state_answers_read_query`
  (old assertion "still acks NotImplemented in 12b.2a" tested transient migration
  behavior that no longer exists). DrainEvents is a real per-context command whose
  body never runs (reply dropped) — exercises the same poison-check-at-routing property.
- `tools_command_context_id: Option<&str> → &str` is correct: Placeholder was the
  only None-returning variant; the return is now total. Removing the phantom Option
  is the right end-state, not backcompat cruft.

**Open coherence finding (root cause — worth raising):** the skeleton-dispatch
scaffold is the un-retired parallel to Placeholder, SAME expired premise.
`spawn_actor` is `#[allow(dead_code)]`, only 2 test call sites; `new_skeleton` +
`skeleton_dispatch` + ~10 `skeleton_dispatch_*` helpers exist only for tests that
exist to test them (circular). Its doc premise is dead: "state still lives on
`ContextManager`" — ContextManager is DELETED (11 stale refs remain in actor/mod.rs,
10 in supervisor.rs — phantom provenance). This PR kills Placeholder but REWRITES
skeleton_dispatch doc from "commit-6 scaffold, replace in commits 7-11" into "the
test-only path for state-less skeleton actors" — recasting transient scaffolding as
a permanent design category (status-quo hardening). KEEP-vs-retire should be decided
on merit; skeleton path's premise expired with ContextManager's deletion.
