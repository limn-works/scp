---
name: pr2235-app-bound-unbound-durable
description: PR #2235 §8.4 AppBound/AppUnbound durable event-log — premise "durable binding" contradicted by ephemeral bound_apps gate never rehydrated from the log; FFI-mirror ceiling read (no JIT resync); stale branch base
metadata:
  type: project
---

# PR #2235 feat/app-bound-unbound-event-log (§8.4 AppBound/AppUnbound)

Interrogated 2026-08-03. Feature = durable event-log appends (tags 74/75) for app bind/unbind
across 3 FFI bridges + 4 SDKs. Actual feature = top 3 commits only
(91138f39b, 254cc36eb, f7392e538); the other ~37 commits in `main..branch` are stale-base
noise (local `main` was behind — still MIN_ACTIVE=55, no durable `bind_app`).

**Root finding (BLOCKER): premise "durable binding" is smuggled.** The whole point is durability,
yet the enforcement/gate state (`FfiBridgeState.bound_apps: HashMap<String,ScopedHandle>`) is
in-memory and NEVER reconstructed from the log. AppBound/AppUnbound land in the state-replay
no-op match arm (state.rs:~1835) — write-only from the enforcement view. After restart: log says
bound, map empty → `app_unbind` is_bound gate (CTX_2059) rejects "not currently bound" though the
durable log (the spec's inspection source of truth per §8.4 line 130) says bound; the ScopedHandle
enforcement is also silently gone. Read-side is non-durable in a feature branded "durable."

**Ceiling/role read (WARNING):** `app_bind` reads `st.ceiling_strings` + `st.role_state` from the
FFI mirror with NO just-in-time resync (`sync_role_state_from_manager_async` /
`sync_ceiling_from_params` exist and are cheap). Consistent with the UCAN/outlet capability-check
status quo (ucan.rs reads `rt.ceiling_strings` the same way) — so not novel unsoundness — BUT bind
writes a DURABLE record of granted caps, so a stale-high mirror (unprocessed remote ModifyCeiling)
gets persisted as an over-grant. The (ceiling, role) read is one atomic `with_ffi_state` closure
(fine); the TOCTOU window is between that read and the separate append+store closures.

**Q3 fail-open (INFO, not reachable):** unbind appends THEN removes from map. The only failure mode
of the post-append `with_ffi_state` is total state-absence → map already gone → no handle leak.
Bind is symmetric (append THEN insert). Ordering defensible; restart-divergence dominates.

**Q5 pipeline assertions 55→57 (SOUND):** the +2 ARE the feature
(`app_bind_wired_through_bind_app_all_bridges`, `app_unbind_...`) — real per-bridge wiring
assertions. The PR-7/ADR-061 STATE_SRC/OUTLETS_INVOKE_SRC assertion churn in the three-dot diff is
stale-base noise, not this feature. Stale base also means `MIN_ACTIVE=57` computed vs a 55 baseline
the real remote main may have already moved past — rebase before trusting the number.
