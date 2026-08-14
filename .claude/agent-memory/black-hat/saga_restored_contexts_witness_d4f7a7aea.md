# RestoredContexts witness RE-ATTACK (commit d4f7a7aea, §17.16.4) — ALL 3 PRIOR BREAKS FIXED

Re-attack of the d4f7a7aea fix for the 3 breaks I proved in d0c57bd75
(see saga_restored_contexts_witness_d0c57bd75.md). All forges COMPILE-PROVEN closed.

## Break 1 (derived Default forge) — FIXED
`RestoredContexts` now `#[derive(Debug)]` only (supervisor.rs:130), private `ids`,
module-private `const fn new`. Compiled probes from scp-ffi (real external crate):
- `RestoredContexts::default()` → E0599 (no Default)  [strict-default, allow_in_memory_custody, testing, --all-features]
- `RestoredContexts { ids: vec![] }` → E0451 (private field)
- `r.clone()` → E0308 (no Clone; autoref-clones the &ref)
- `RestoredContexts::for_test(..)` → E0599 in EVERY shipped feature combo

## Break 2 (for_test feature-unification leak) — FIXED (regression closed)
for_test now `#[cfg(feature="saga-witness-test-mint")]` (supervisor.rs:162); feature is
`[]` in scp-runtime/Cargo.toml:32, NOT implied by `testing`. Only enabler = required-features
of 2 actor_saga_* test targets (Cargo.toml:130,134). REGRESSION PROOF: the OLD leak chain
`cargo build -p scp-ffi --lib --features allow_in_memory_custody` that COMPILED for_test under
d0c57bd75 now → E0599. `cargo tree -p scp-ffi --features allow_in_memory_custody` shows
scp-runtime resolves to `allow_unencrypted_storage,testing` — saga-witness-test-mint ABSENT.
scp-ffi has NO direct scp-runtime dep (can't forward the feature; `--features
scp-runtime/saga-witness-test-mint` errors "does not contain this feature"). Only scp-core
directly deps scp-runtime, maps only testing→testing + allow_unencrypted_storage. No shipped
crate forwards saga-witness-test-mint. AIRTIGHT.

## Break 3 (UFCS-evadable bridge text gate) — FIXED via behavioral bootstrap test
New test `bridge_restore_entry_runs_restore_and_replay_legs`
(scp-testing/tests/integration/saga_bridge_bootstrap.rs) drives the REAL shared bridge entry
`CoreFields::restore_all_persisted_contexts` over real persistence (Active ctx) + durable
ProtocolRepositorySagaJournal (orphaned Initiated entry); asserts LEG1 ctx resident AND LEG2
saga reconciled to terminal. NEGATIVE CONTROLS (mutated real bridge body, ran test):
- `restore_all_contexts().into_ids()`-then-stop → test FAILS LEG2 "replay never ran"
- UFCS+shadow (`Supervisor::restore_all_contexts(sup)` + no-op `restore_on_startup` closure):
  PASSES the text gate (gate still UFCS-evadable — confirmed) but FAILS bootstrap LEG2.
The exact d0c57bd75 evasion is now behaviorally caught. Both-legs property is sound.
compile_fail forge doctests on replay_unresolved_sagas (supervisor.rs:5575,5588): flipping the
struct-literal one to runnable → E0451 (proves seal reason, NOT signature drift). Not tautologies.

## Attack 5 (CI feature threading → artifact) — SAFE
saga-witness-test-mint threaded into ci.yml (clippy/nextest/doc), docs.yml, release.yml:94,
build-matrix.yml:86 — but ALL are `cargo test`/clippy/doc VERIFICATION steps. The
artifact-producing steps are feature-free: build-matrix.yml:81 `cargo build --release` (no
features); wheel=maturin no-feature; napi/xcframework/AAR/cbindgen = `cargo build -p X --release`
no-feature. Upload glob (build-matrix:92-96) = release/ ROOT (libscp_core*/scp_core*/libscp_ffi*),
test bins live in release/deps/<name>-<hash> — never matched. No artifact bundles for_test.

## Attack 4 (with_providers_and_journal now pub) — NON-FINDING
It's a thin body shared with with_providers (which just passes NoopSagaJournal); NO validation
bypassed. Journal injection = same trust level as the other injected providers
(transport/persistence/crypto) — supervisor builder is the trusted bootstrap authority, no
privilege boundary crossed. Commit's claim "Supervisor::new already accepts arbitrary journal"
is imprecise (new is `#[cfg(any(test,feature=testing))]`, testing-gated) but posture unchanged.

## ORTHOGONAL MEDIUM (pre-existing, NOT this commit's scope)
Production bridges (scp-ffi/src/runtime.rs:1217 build_supervisor; bridge_instance.rs:2876) build
the supervisor via `Supervisor::with_providers` which HARDCODES NoopSagaJournal (supervisor.rs:1379).
No durable ProtocolRepositorySagaJournal is wired in the production bootstrap path, so
replay_unresolved_sagas sweeps a no-op journal in prod (nothing to reconcile). The durable-journal
attachment ("bridge attaches a durable journal separately" per docs) is not yet present in the
bridge construction. Separate Phase 2D/2E integration gap, not a regression of the witness seal.

## Net
All 3 claimed fixes HOLD under compiled re-attack. The type seal is now airtight (no Default/Clone/
literal/for_test forge in any shipped build); the for_test leak regression is closed and
structurally bounded by feature-graph topology; the bridge both-legs property is enforced
behaviorally (UFCS-evades text gate but not the bootstrap test). Witness is no longer theater.
