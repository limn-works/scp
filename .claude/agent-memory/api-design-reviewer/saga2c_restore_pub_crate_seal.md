---
name: saga2c-restore-pub-crate-seal
description: Review of 7da90cb61 (saga-2c) narrowing Supervisor::restore_all_contexts pub->pub(crate); approved with one stale-comment finding
metadata:
  type: project
---

Commit `7da90cb61` (worktree saga-2c, ADR-049 §17.16.4 restore-then-replay recovery), API-design review verdict: APPROVED, ONE non-blocking finding.

**Why:** Three doc/visibility follow-ups. FIX A rewrote `with_providers_and_journal` rationale (old text cited test/testing-gated `Supervisor::new` as a `pub` precedent — false in prod; corrected to cite unconditionally-`pub` `with_providers`). FIX B relabeled `BridgeInstanceCore::restore_all_persisted_contexts` -> `CoreFields::restore_all_persisted_contexts` (it's a CoreFields inherent method reached via the trait's `resume` default body). FIX C narrowed `Supervisor::restore_all_contexts` `pub`->`pub(crate)` to seal the bare restore-without-replay leg cross-crate (E0624).

**Verified facts (supervisor.rs unless noted):**
- `Supervisor::new` IS `#[cfg(any(test, feature="testing"))]`-gated (line ~1219) — FIX A premise correct.
- `with_providers` unconditionally `pub` (1354), delegates to `with_providers_and_journal` with `Arc::new(NoopSagaJournal)` (1381) — corrected precedent correct.
- `restore_on_startup` (pub, 8088) consumes the `RestoredContexts` witness from `restore_all_contexts` then calls `replay_unresolved_sagas`; public entry is restore_on_startup, bare leg is the internal first sweep. pub(crate) is coherent.
- Production bridge path `CoreFields::restore_all_persisted_contexts` (bridge_instance.rs 1695) already routes through `supervisor.restore_on_startup()` (1707) — narrowing does NOT break it (different crate, but goes through the public combined entry).
- WASM `mgr.restore_all_contexts()` (wasm/src/context.rs 1248) is a WASM-LOCAL manager (ADR-034 re-impl), NOT scp-runtime Supervisor — unaffected.
- `RestoredContexts` witness stays `pub` w/ pub ids()/into_ids(); only `new` minter module-private. Surface coherent.

**FINDING (low/nit, NON-BLOCKING):** `crates/scp-testing/tests/integration/pipeline_wiring.rs:921-925` comment still says `restore_all_contexts` is kept `pub` and "a bridge COULD physically name the bare leg." After FIX C this is stale/contradictory cross-crate (commit message itself says E0624). FIX A corrected this exact class of stale-`pub`-claim elsewhere but missed this block. Recommend updating to note the cross-crate caller can no longer name the bare leg; the substring gate remains in-crate defense-in-depth.

How to apply: if asked to re-review after a fix, confirm the pipeline_wiring.rs:921 block was updated. Pattern worth remembering: visibility-narrowing commits frequently leave stale "kept pub" rationale comments in adjacent enforcement-gate files.
