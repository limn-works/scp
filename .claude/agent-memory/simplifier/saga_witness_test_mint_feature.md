---
name: saga-witness-test-mint-feature
description: §17.16.4 RestoredContexts witness seal — why the dedicated cargo feature (not `testing`) is the minimal forge-fix, and the two-persistence-slot gotcha
metadata:
  type: project
---

`RestoredContexts` (scp-runtime supervisor.rs) is a sealed witness token proving a real
`restore_all_contexts` ran before `replay_unresolved_sagas` (§17.16.4 restore-then-replay
ordering). Sealed: private `ids`, module-private `new`, NO `Default`/`Clone`. Consumed by
value via `into_ids()` — that's why `Clone`/`Default` removal is safe.

The test-only `RestoredContexts::for_test` minter is gated behind a DEDICATED leaf cargo
feature `saga-witness-test-mint` (`= []`), NOT `testing`.

**Why:** a `testing`-gated minter leaks into every `allow_in_memory_custody` build via
`scp-ffi → dep:scp-testing → scp-core{testing} → scp-runtime/testing`, re-opening the forge.
The dedicated feature is enabled ONLY by the `required-features` of the `actor_saga_coordinator`
+ `actor_saga_crash_recovery` test targets, so no production/FFI build reaches the back-door.

**How to apply:** if asked whether the coordinator tests could mint a real witness instead of
`for_test` (eliminating the feature): NO. Those tests build via `Supervisor::new`, which sets the
direct `persistence` field but leaves the `helper_persistence` OnceLock EMPTY. `restore_all_contexts`
reads `helper_persistence` (via `persistence_ref()`), NOT the `persistence` field — so it returns
`PersistenceFailed`. Only `with_providers*` populates `helper_persistence`. The two-persistence-slot
split is the load-bearing detail. Switching all 6 coordinator call sites to
`with_providers_and_journal` would force the full heavy provider bootstrap (MLS/transport/event-log/
key-resolver/mls-storage) for a lightweight replay-in-isolation test — a worse tradeoff than the
feature. `for_test` + feature is warranted.

CI threading the feature into `--features` lists is NECESSARY (not redundant): `required-features`
makes cargo SILENTLY SKIP the target when the feature is absent, so without threading the saga
targets just wouldn't run.

The bridge-path enforcement was correctly reframed per CLAUDE.md §189: the UFCS-evadable source-text
gate `bridge_resume_path_routes_through_restore_on_startup` was honestly downgraded to "best-effort"
and the behavioral `bridge_restore_entry_runs_restore_and_replay_legs` integration test
(scp-testing/.../saga_bridge_bootstrap.rs) became the sound both-legs enforcement — the right move,
not denylist-grinding.
