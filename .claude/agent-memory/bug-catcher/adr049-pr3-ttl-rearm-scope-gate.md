---
name: adr049-pr3-ttl-rearm-scope-gate
description: ADR-049 PR-3 pass-4 H1 fix regression — memory_scope==Full gate on TTL re-arm breaks Full+ttl contexts
metadata:
  type: project
---

# ADR-049 PR-3 (feat/adr049-pr3-live-timers) pass-4 review

The H1 fix (commit ae965aa53) gated restore/import TTL re-arm on
`params.ttl.is_some() && memory_scope != MemoryScope::Full`
(lifecycle_helpers.rs ~2469 import, ~3071 restore).

**Why the gate is wrong:** TTL and memory_scope are ORTHOGONAL (spec 05-contexts
§5.11 line 485: "When TTL expires, key destruction follows the memory scope").
Full-scope + ttl=Some is a valid, reachable config:
- Broadcast contexts REQUIRE Full (memory_scope.rs validate_memory_scope_for_broadcast)
  and CAN have a TTL — see params.rs:1087 test (Broadcast+Full+ttl=1h+PublicBroadcast).
- Encrypted+Full+ttl also valid; no validation rejects Full+ttl.
- finalize_create arms TTL whenever ttl.is_some() (no scope gate) → expires on first run.
- Restore rebuilds ttl.timer via TtlTimer::with_clock → deadline None; ONLY the re-arm
  gate re-populates it. Gate skips Full → never re-arms → never expires post-restart.

**Root cause:** promoted vs Full-created are indistinguishable by (memory_scope, params.ttl).
Both Full, both ttl=Some. Promotion only clears deadline (params append-only). Correct fix
needs an explicit persisted `promoted`/`ttl_removed: bool` in ContextSnapshot set by
execute_promote_context; gate on `!snapshot.promoted`. Also resolves D1 create-window.

**Test gap:** restore_promoted_context_does_not_re_expire passes for the buggy behavior
(only tests promoted case). No test covers "Full-scope context CREATED with a TTL re-arms
on restore".

Other pass-4 items verified CLEAN: H2 (no-op reset on no-TTL), M2 (leaf-before-relay +
bounded exp backoff, no overflow), M1 (convergent retry leaf), M3 derive_extension_bound
(no panic, safe decode), N5 is_terminal() (pure refactor), L1 persist-gate (correct).
