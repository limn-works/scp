# Saga bridge-bootstrap + RestoredContexts seal tests (commit d4f7a7aea, branch feat/2c-saga-dispatch)

Follow-up to [[saga-restore-replay-recovery-tests]] — closes the residual gap that memory flagged at line 17 ("no test exercises the restoration-dependent residency path through the BRIDGE entry").

## bridge_restore_entry_runs_restore_and_replay_legs (scp-testing/tests/integration/saga_bridge_bootstrap.rs)
- THE strongest test in the delta. Drives the REAL shared bridge entry `CoreFields::restore_all_persisted_contexts` (what all 3 non-WASM FFI bridges delegate to) over shared SharedPersistence + durable ProtocolRepositorySagaJournal + SHARED OpenMLS storage (must share all 3 backing stores across the "crash").
- Two-process model: sup1 creates+flushes an Encrypted (MLS) Active ctx then drops (=crash); a crash-orphaned `Initiated` journal entry is appended; sup2 (fresh, same stores) restores via the bridge entry.
- Asserts BOTH legs by OBSERVABLE EFFECT (not Result — the bridge entry returns `()` and swallows errors): leg1 = `read_context_state(ctx)==Some(Active)` (was None pre-restore, explicit pre-condition asserted), leg2 = saga gone from `load_unresolved`.
- NON-VACUOUS: `Initiated` recovery arm (supervisor.rs:5627) marks Aborted→resolved with NO actor/caller dependency — minimal both-legs probe, correct choice. Pre-conditions asserted (ctx persisted+Active before crash; saga unresolved before restart; ctx non-resident before restore).
- "Could it pass if replay silently didn't run?" NO — leg2 directly reads the journal; bridge swallowing a replay error would leave the entry unresolved → assert fires with the `{unresolved:?}` diagnostic.
- NEGATIVE CONTROL: not a literal commented-out call, but genuine — removing the bridge call leaves ctx non-resident (leg1) AND saga unresolved (leg2), both fail. Order-discrimination is NOT this test's job (it seeds Initiated, not PreparingB); order is pinned by the from-persistence unit test + structural gate. Honest scoping.
- Low flake: multi_thread worker_threads=2 (block_in_place in restore path). Deterministic ids/keys/timestamps. No sleeps/wall-clock/random.
- Mild duplication: SharedPersistence + SharedPersistenceArc are two near-identical ContextPersistence impls (newtype to share the Arc past an owned-Box constructor). Acceptable test plumbing; could collapse if `with_providers_and_journal` took `Arc<dyn>`.

## RestoredContexts seal + compile_fail doctests (supervisor.rs)
- Forge closure: dropped `derive(Default, Clone)` → `derive(Debug)`; `for_test` re-gated `testing`→dedicated `saga-witness-test-mint` feature (the testing gate leaked into allow_in_memory_custody via scp-ffi→dep:scp-testing→scp-core{testing}→scp-runtime/testing). `with_providers_and_journal` widened pub(in crate::context)→pub for the cross-crate bootstrap test.
- 3 compile_fail doctests are MEANINGFUL, not tautological: (1) replay-first body doesn't compile (witness REQUIRED), (2) `RestoredContexts::default()` E0599 (no Default forge), (3) `RestoredContexts { ids: vec![] }` E0451 (private-field forge). Each is an EXTERNAL-crate compile pinning a real attenuation the prior 0-arg doctest (now deleted) did not. Commit claims each verified to fail for the right reason.

## Dedup via stage_xctx_preparing_b_crash
- Extracts ~95% shared setup of the two PreparingB crash tests (journal Initiated/PreparingA + dispatch_xctx_prepare_a + flush + void-carrier + journal PreparingB). Returns (sup, persistence, caller_hex, burst_milli).
- DISCRIMINATING POWER PRESERVED for the order-discriminating `restore_on_startup_restores_caller_from_persistence_then_delivers_reversal`: its UNIQUE assertions (despawn, lookup-none pre, `restored` contains caller_hex, lookup-some post, token==burst, record consumed, terminal) all remain INLINE in the test body, NOT moved to the helper. Helper just stages. Confirmed by reading 18680-18771.
- The Active-snapshot assertion that lived only in the from-persistence test is now in the helper (runs for BOTH tests) — net STRENGTHENING of the resident test, no assertion lost. Both `#[allow(too_many_lines)]` dropped.
- Helper takes `persistence: CapturingPersistence` param → caller picks `::default()` (restore-disabled) vs `::with_restore()`. The one knob that distinguishes the two tests stays at the call site. Good factoring.

## Residual (unchanged from prior memory, still true)
- Err-conservative branch of `caller_context_deleted_from_persistence` (storage error → treat as present, don't reap) still untested.
