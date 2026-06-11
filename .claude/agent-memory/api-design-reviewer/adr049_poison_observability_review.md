---
name: adr049-poison-observability-review
description: ADR-049 §10 poison/crash observability surface review — Swift ContextState ordinal, error-code taxonomy, honesty docs across bridges
metadata:
  type: project
---

ADR-049 §10 actor poison/crash observability surface (Phase 2B round-2, worktree feat/actor-2b-watchdog-respawn, HEAD 2490db0c5). Verdict: APPROVED with 2 non-blocking doc-staleness items.

**Why:** Round-1 found `Poisoned` unobservable via `state()` + Swift coerced unknown→`.active`. Remediation: documented poison surfaces via error code, added Swift `.poisoned` case + fail-safe default.

**How to apply (durable facts for future poison/state reviews):**
- UniFFI `ContextState` enum ordinals are 1-based declaration order, no explicit discriminants: Creating=1, Active=2, Closing=3, Closed=4, Expired=5, MigratingOut=6, Tombstoned=7, Poisoned=8. Hand-added Swift `ScpBindings.swift` converter case 8 ↔ Int32(8) ↔ `.poisoned` is CORRECT.
- The LIVE lifecycle path is the `String`-returning `state()` (uniffi bridge.rs:~2327, returns "poisoned" etc). The `ContextState` by-value enum + FfiConverter is DEAD at the FFI boundary (no exported fn returns/takes it by value) — load-bearing Swift logic is `Context.mapStateString` (Context.swift:251), which fail-safes unknown→`.poisoned`.
- Error-code taxonomy: SCP-CTX-2134 = ContextPoisoned (budget exceeded, dormant, operator recovery), SCP-CTX-2135 = ActorCrashed (lost/corrupt snapshot OR mid-respawn race). Mapped in PyO3 + NAPI error.rs with tests + a generic→2001 regression guard. WASM correctly has NEITHER (no actor supervisor per ADR-034).
- Honesty contract (now accurate in ADR §10 + PyO3 docstring): cached `state()` is best-effort, NOT a live read; watchdog poison does NOT write the per-handle cache; authoritative signal is the error code on the next op; recovery = `SupervisorHandle::clear_poison`/restart, NOT an SDK call. `read_context_state` reports Poisoned only from sticky `crash_windows` flag. `lookup_miss_error` (supervisor.rs:3258) is the 2134/2135 split source.

**Open doc-staleness items flagged (non-blocking):**
1. Context.swift:5 header comment lists only 5 of 8 ContextState cases (omits migratingOut/tombstoned/poisoned).
2. uniffi bridge.rs:~2321 `state()` doc "One of:" list omits "poisoned" though the match arm returns it; PyO3 sibling was updated, UniFFI was not.

See [[feedback-bash-cwd-main-worktree]] — had to re-pin git to the worktree to avoid a false "missing enum case" finding.
