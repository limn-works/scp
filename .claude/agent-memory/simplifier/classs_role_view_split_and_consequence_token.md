---
name: classs-role-view-split-and-consequence-token
description: ADR-049 §9 Class-S — why the two role views / parts seam / SharedClassS / token are NOT over-engineered, and why the consequence-split fix should be a &mut Option<Token> sink not a returned token
metadata:
  type: project
---

`crates/scp-runtime/src/context/actor/class_s.rs` (~6400 lines incl. tests). Assessed on branch `classs-fin-trunk` @ `beddb1c70`.

The §9 guarantee is "every authorization/replay-state mutation is fail-closed-persisted, enforced at compile time." Each abstraction maps 1:1 to a borrow-checker fact, not gold-plating:

- **Two role views** (`RoleStateClassCMut` general / `ConsequenceRoleStateMut` consequence-only): the ONLY difference is the GROW pair `suspend_capabilities`/`suspend_all`. Collapsing them re-opens BLACK-CS-03 (a best-effort caller could GROW with no fail-closed persist). The split is the confinement; it is load-bearing, not redundant. Shared body lives in `scp-protocol::ContextRoleClassCParts::system_assign_role`, so duplication is method-surface only (~40 lines), the minimum cost of structural confinement.
- **`ContextRoleClassCParts` (parts seam)**: the cross-crate disjoint-destructure that lets `scp-protocol`'s now-`pub(crate)` `ceiling`/`suspended_capabilities` be privatized while `scp-runtime` still borrows them field-granularly. Without it you cannot privatize → cannot confine GROW. Necessary.
- **`SharedClassS`**: turns a one-token `&` → `&mut` flip into 3 conspicuous central edits; backstopped by `assert_not_impl_any!(SharedClassS: DerefMut)`. Cheap (3 methods), proportionate to BLACK-CS-01.
- **`ClassSCommitToken`**: the deferred-persist linear handle (begin_class_s / _conditional already returns `Option<Token>`). Not redundant with combinators — covers the EARLY-consume-LATE-ack shape (burned nonce).
- **brace-depth tripwire**: a bounded POSITIVE allowlist (`class_s_no_persist_mutator_whitelist_is_bounded`), sound+convergent, NOT the retired 4354-line denylist scanner. Keep.

GENUINE residue (not over-engineering, just incomplete migration): `commit_class_s_compensating` + `commit_class_s_then_append` have NO production caller (`#[allow(dead_code)]`); ~10 scaffolding `#[allow(dead_code)]` blocks await handler migration. These should converge to zero as handlers migrate — track that they do, don't let them ossify.

CONSEQUENCE-TOKEN FIX (part 2 verdict): the proposed `consequence_split()`-returns-`#[must_use]`-token is the RIGHT pattern BUT must be a `&mut Option<ClassSCommitToken>` SINK, not a return value. Reason: `settle_tool_economy_capture` (tools_helpers.rs:868) applies the downward-auth mutation in memory BEFORE a fallible payment capture that early-returns `Err` via `?`. The `downward_auth_sink: &mut bool` was created SPECIFICALLY so the obligation survives that `?`. A returned token has the identical stranding problem the bool sink already solved. So: reuse the EXISTING `ClassSCommitToken` (no new type), but thread it as `&mut Option<Token>` mirroring the bool. `enforce_triggered_consequences` is already `#[must_use]` (governance_logic.rs:177) — the gap is downstream threading/persist-gating, which a token closes and the bool doesn't. Net: justified, reuses existing token type, NOT a second abstraction.
