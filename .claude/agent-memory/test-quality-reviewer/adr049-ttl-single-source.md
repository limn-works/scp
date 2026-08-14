---
name: adr049-ttl-single-source
description: TTL-deadline single-source redesign (ADR-049 PR-3) test suite — strong regression gates + the residual coverage gaps
metadata:
  type: project
---

ADR-049 PR-3 "live timers" redesign: event log is the SINGLE authoritative source of the convergent TTL deadline. Every reader derives via `convergent_ttl_deadline(&[Event], creation, params_ttl)` in `crates/scp-runtime/src/context/ttl_close_helpers.rs` (~569). Old competing sources DELETED: `derive_extension_bound`/`ExtensionBound` clamp machinery (export_import.rs), `memory_scope != Full` restore gate (lifecycle_helpers.rs).

**Why:** collapse the 4 competing deadline sources that produced H1/M1/M3/D1/D2 bugs.

**Strong gates (worth replicating):**
- Import over-long-scalar divergence gate: `import_ignores_over_long_scalar_derives_from_log` (supervisor.rs 16266) — scalar=creation+1yr, log=[Created] → arms creation+1h. Maximal scalar/log divergence; log wins. The single best single-source gate.
- Terminal-leaf retry derivation: `retry_stamps_convergent_leaf_timestamp` (15013) + reset variant (15138) — Phase-1 clears scalar to None, retry must re-derive from log (not now()).
- Reset emits leaf: `reset_ttl_timer_emits_ttl_extended_leaf` (14844); no-op emits none: `reset_ttl_on_no_ttl_context_does_not_expire` (14782).
- H1 companion: `restore_created_full_scope_with_ttl_re_arms` (14377) — Full-scope+ttl MUST re-arm (catches reintroduced memory_scope gate).

**Residual gaps (minor, flag on re-review):**
1. `convergent_ttl_deadline` has NO extension-below-base unit test (ext < create base). `.max()` guards it but a regression to `ext.unwrap_or(base)` (ignoring base when a stale/lower leaf present) escapes. Also untested: promote-then-recreate ordering (`> created_seq` guard), multiple ContextCreated.
2. Restore-path scalar-override only half-gated: `restore_promoted_context_does_not_re_expire` (14289) sets scalar=None, so it does NOT force a stale non-None scalar to be overridden by a log-derived None. Import path covers the class; restore does not.
3. `consented_dids()` sort-for-convergence (ttl.rs) untested with 2+ members — the emits-leaf test uses ONE consenter, so removing `sort_unstable` escapes.
4. reset_ttl_timer leaf-append-failure fallback (extension lost → re-derive base, fail-safe) untested.

**Comment nit:** import test prose still says "clamp/clamped" though the redesign REMOVED clamping (now pure derivation) — contradicts CLAUDE.md honest-comment rule.

Round-2 nits confirmed fixed: `#[cfg(feature="testing")]` moved off the pure `ttl_expiry_retry_backoff_is_bounded_exponential` test onto `incomplete_cleanup_keeps_actor_alive_and_retries` (actor/mod.rs 2141); 2-round backoff added: `ttl_expiry_retry_backoff_grows_across_two_rounds` (2124).
