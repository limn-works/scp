# ADR-070: Split scp-runtime into Types, Core, Domain and Assembly Crates

**Status:** Accepted 2026-11-03. Alec approved the split and its enforcement-file changes on 2026-11-03: "Yes split it do it all in one go".

**Corrected 2026-11-03:** the execution plan (`~/.claude/plans/runtime-split-plan.md`, §0 "Inventory check against main") checked this record against `main` and found six corrections, which this record now carries:
1. Five domain sites read `ActorDeps::owned_identity`, which a domain crate cannot reach. Core adds `ActorDeps::my_wrapping_key` (§How ADR-049 stays intact, Decision 5).
2. `context/pseudonym_rotation_runtime_tests.rs` and three other context test files move to the messaging crate, not to core (§Decision item 5).
3. The pre-commit hook's `CLIPPY_FEATURES` is at `scripts/hooks/pre-commit:164`, and the hook now lints only the members a commit changes (§Context, §Enforcement files).
4. `pipeline_wiring.rs` `MANAGER_SRC` adds each core file that receives a function it asserts on (§Enforcement files).
5. The lifecycle trait names its import method `import_context_from_export` (§Decision item 3).
6. The pyo3 caller pattern of the `callback-custody-record-store-at-create` call invariant is fixed in the same commit as the zero-match assertion (§Enforcement files).

**Corrected 2026-11-04:** review of the implementing pull request found that the scan behind the Appendix counted calls inside `supervisor.rs`'s `#[cfg(test)] mod tests` (line 19342 onward on `main`) as calls from core. Eight functions have no other core caller: `broadcast_helpers::block_broadcast_subscriber` and `unblock_broadcast_subscriber`, `governance_helpers::execute_propose_context_migration` and `execute_revoke`, `lifecycle_helpers::close_context`, `messaging_helpers::decrypt_and_dispatch` and `finalize_send`, and `ttl_close_helpers::reset_ttl_timer`. The Appendix now tags each of them `[core tests]`, and no trait declares them. Core calls 55 distinct domain functions, not 63, and 98 functions, not 106, cross a domain boundary in production code. The same review added the `shared/` rule to §2, the request-struct rule to §3 and the injection trust boundary to §4.

**Amends:** ADR-049 (actor per context) in where its handler code lives: the handlers move out of `crates/scp-runtime/src/context/actor/handlers/` into one crate per domain. Every numbered ADR-049 decision keeps its rule; §How ADR-049 stays intact gives the argument for each one this split touches. `.docs/architecture.md` §2.1 gains the new crates.

**Plan:** `~/.claude/plans/local-speed-2026-11.md`, section "Proposal: split scp-runtime (not implemented)". Alec's words for the goal: "I don't care how but make local loop faster like I told you to……" and "as fast as theoretically possible."

## Context

Agents edit `scp-runtime` more than any other crate. Two waits follow every edit:

1. **The lib-test rebuild:** `cargo test -p scp-runtime --features testing --lib --no-run`. It recompiles the whole crate in its test configuration, which is 221k production lines and 67k test lines in one compilation unit.
2. **The pre-commit hook's clippy chain:** when this record took its measurements, `scripts/hooks/pre-commit` ran clippy over the edited crate and every workspace crate that depends on it. Cargo has no early cutoff, so the hook re-linted every dependent even when the edit changed no signature. A later hook change, "lint and format only the members a commit changes", made the hook lint only the workspace members that hold a changed path and leave their dependents to CI's workspace clippy. The hook figures in §Measurements predate that change.

The plan recorded ≈66 s for the lib-test rebuild on an idle machine. I could not reproduce that figure on `main` at the commit this record was written against. Both edit kinds I measured rebuild in 7.5 to 9.5 s, as the table below shows. The ≈66 s figure may come from a different edit kind or from the time-passes build the plan used. Every comparison in this record is against today's measured baseline, not against ≈66 s.

### Method

- Machine: the 16-core Mac in the plan. rustc 1.97.1 stable, `[profile.dev] debug = "line-tables-only"`, non-member dependencies at opt-level 1, one shared `CARGO_TARGET_DIR` per measurement set, `RUSTUP_TOOLCHAIN` unset.
- Edit kinds:
  - **Literal edit:** insert one character into a string literal inside a function body, then remove it on the next run. Each run is a real recompile that leaves the crate's shape unchanged.
  - **Item edit:** add a new `pub fn` after that literal.
- Each figure is the minimum wall time of 3 runs. The load average is the 1-minute figure that `sysctl vm.loadavg` reported before the runs. Other sessions were building on the machine during every set, so the load was never below 5.
- Prototypes: two scratch trees built from `main`.
  - **Cut 1** moved 40 modules (the list in §Decision, item 1) into a new `scp-runtime-types` crate below `scp-runtime`.
  - **Cut 2** copied the governance domain (`governance_helpers.rs`, `governance_logic.rs`, `actor/handlers/governance.rs`, 11.8k lines) into a new `scp-runtime-governance` crate above `scp-runtime`, and made `scp-core` and `scp-testing` depend on it so the hook re-lints the same downstream chain it would after the real split.
  - Both prototypes compile with their tests and pass `cargo clippy --all-targets`. Neither is a design: cut 1 relocated tests that reach private items, and cut 2 widened every restricted visibility in `scp-runtime` to `pub` so the copies resolve.

### Measurements

| Measurement | Baseline (`main`) | Cut 1: types crate | Cut 2: governance crate |
|---|---|---|---|
| Literal edit in moved code, that crate's lib test | — | `crypto/ucan/mint.rs`: **1.2 s** (2.5 s CPU, load 8.6) | `governance_helpers.rs`: **0.9 s** (2.2 s CPU, load 9.5) |
| Item edit in moved code, that crate's lib test | — | **1.7 s** (load 6.2) | **1.4 s** (load 6.3) |
| Literal edit in moved code, lib tests of the new crate and `scp-runtime` | — | 5.2 s | — |
| Literal edit in `actor/handlers/messaging.rs`, `scp-runtime` lib test | 7.5 s (load 5-6); 8.3 s (load 8-9) | 6.8 s (load 7) | 7.5 s; 6.8 s for both crates' lib tests |
| Literal edit in `supervisor/supervisor.rs`, `scp-runtime` lib test | 5.2 s (load 5-6) | 5.1 s | — |
| Literal edit in `governance_helpers.rs`, `scp-runtime` lib test | 7.2 s (load 5-6); 9.5 s (load 8-9) | 8.1 s | (moved) |
| Item edit in `actor/handlers/messaging.rs`, `scp-runtime` lib test | 8.4 s (load 9.7) | 7.2 s (load 6.1) | — |
| Item edit in `governance_helpers.rs`, `scp-runtime` lib test | 9.2 s (load 7.2) | — | (moved) |
| Literal edit in `actor/handlers/messaging.rs`, production lib only (`cargo build --lib`) | 3.1 s (load 6.6) | — | — |
| Hook clippy chain, literal edit in the moved code | — | 20.2 s (load 12.6) | **13.7 s** (70 s CPU, load 13.6) |
| Hook clippy chain, literal edit in `actor/handlers/messaging.rs` | 22.9 s (98-115 s CPU, load 13-14) | 20.7 s | 20.2 s |
| Cold build of the edited crates | — | 32.6 s | — |

The hook figures use the hook's crate scope with `--all-targets` and the hook's features, without `-D warnings`.

Three facts follow from the table:

1. **A crate of 12k to 36k lines rebuilds its lib test in 0.9 to 1.7 s.** That is the floor this machine reaches for a crate that links the full runtime into its test binary. Cut 2's figure includes linking that binary.
2. **Test code is most of the baseline's rebuild.** After the same messaging edit, the production lib rebuilds in 3.1 s and the lib test in 8.3 s.
3. **The downstream re-lint is a floor of about 13 s for the hook.** A governance edit in cut 2 re-lints governance and every downstream crate in 13.7 s. Below that, only a hook that stops re-linting unchanged dependents helps, and the crate split does not do that. The later hook change named in §Context stopped that re-lint.

### Where agents edit

`git log` over the 60 days to 2026-11-02 shows 625 file changes in `crates/scp-runtime/src` across 69 commits. Under the decision below they would land as follows:

| Crate | File changes | Share |
|---|---|---|
| `scp-runtime-core` | 399 (supervisor.rs alone: 45) | 63.8% |
| The 13 domain crates | 170 | 27.2% |
| `scp-runtime-types` | 56 | 9.0% |

The most edited files are `supervisor/supervisor.rs` (45), `lifecycle_helpers.rs` (28), `governance_helpers.rs` (19), `supervisor/spawn_from_welcome_tests.rs` (18), `actor/state.rs` (17), `messaging_helpers.rs` (17), `actor/mod.rs` (15) and `actor/commands.rs` (15).

### How domain code and core code reach each other today

The decision depends on four counts from production code, with comments excluded:

- **Core calls 55 distinct domain functions.** The actor's dispatch hub calls 13 `dispatch` functions. `supervisor/supervisor.rs` calls 31 others, among them `lifecycle_helpers::create_context`, `import_context` and `restore_context`, and `ttl_close_helpers::handle_ttl_expiry`. This record first counted 63, because its scan read eight calls inside `supervisor.rs`'s test module as production calls (§Corrected 2026-11-04).
- **Domains call 62 distinct items in other domains.** Examples are `messaging_helpers::persist_state_best_effort`, which seven domains call, the nine economy enforcement functions that lifecycle and messaging call, and `governance_helpers::try_broadcast_commit`.
- **Functions and types called across a domain boundary:** together, these come to 98 distinct functions and 28 types or constants. The Appendix lists them, together with the eight functions tagged `[core tests]`.
- **Test code that builds a Supervisor:** 15.6k of the 16.7k test lines in domain files, and 33.6k of the 51.7k test lines in core files.

## Options considered

Each option states what it asserts, what it costs, and what its measured or estimated numbers are. An estimate is labelled as one.

### Option A: keep one crate

- **Asserts:** nothing changes.
- **Loop:** 7.5 to 9.5 s per lib-test rebuild for every edit, and 22.9 s for the hook.
- **Costs:** no migration, and no enforcement-file change.
- **Why it loses:** Alec asked for the fastest loop possible, and this option leaves every edit at the baseline.

### Option B: the types crate only

- **Asserts:** the 40 leaf modules in §Decision item 1 move into `scp-runtime-types`, below `scp-runtime`. Nothing else moves.
- **Loop:** an edit in the types crate rebuilds its lib test in 1.2 to 1.7 s. These edits are 9% of file changes. Every other edit stays at 5.1 to 8.1 s. The hook is 20.2 s for a types edit, since everything above re-lints.
- **Costs:** visibility widening for the types the runtime reaches, and test relocation for tests that use runtime private items. Cut 1 needed seven items made `pub` and one `cfg(test)` helper widened to `cfg(any(test, feature = "testing"))`.
- **Why it loses alone:** it leaves the 27% of edits that land in domain code at the baseline. It is part of the decision below.

### Option C: types crate plus one crate holding all 13 domains

- **Asserts:** domain code (38k production lines) moves into one `scp-runtime-domains` crate above core. The `DomainHandlers` mechanism below attaches it.
- **Loop (estimate, not measured):** a domain edit rebuilds a lib test of about 38k production lines plus 16.7k test lines. Cut 1's 36k-line types crate took 1.2 s, so I estimate 1.5 to 2.5 s.
- **Costs:** the same trait surface as Option D for core-to-domain calls (55 functions), and no trait surface between domains, because domains share one crate.
- **Why it loses:** it is slower than Option D for every domain edit, and its one advantage disappears under Option D's rule. Cross-domain calls through core traits cost Option D one indirection per call, and Option C saves only that.

### Option D: types crate, core crate, 13 sibling domain crates, assembly crate (chosen)

- **Asserts:** every domain becomes its own crate. No domain crate depends on another. Each depends on `scp-runtime-types` and `scp-runtime-core` only, and reaches core or another domain through traits that core defines.
- **Loop:** a domain edit rebuilds that crate's lib test in 0.9 to 1.4 s, measured on governance, the largest domain at 10.9k production lines. These edits are 27% of file changes. The hook takes 13.7 s for a domain edit.
- **Loop for core edits (estimate, not measured):** core edits rebuild a lib test of 157k production lines plus the 18.1k test lines that stay in core. The production lib alone rebuilds in 3.1 s and the current lib test in 8.3 s, so I estimate 4 to 5 s. These edits are 64% of file changes.
- **Costs:**
  - A trait surface of at most 98 methods across 13 traits, plus 28 types and constants that move to core.
  - 33.6k core test lines move to the assembly crate, and the core items those tests reach become visible under the `testing` feature.
  - 15 new manifests, and the enforcement changes in §Enforcement files.
- **Why it wins:** it is the only option in which a domain crate's own tests can build a full Supervisor. A domain crate's tests dev-depend on the 12 sibling domain crates. None of those depends on the crate under test, so the test binary links one copy of it.

### Option E: layered domain crates, each depending on the domains below it

- **Asserts:** domain crates stack in one order that minimizes upward references. The best order found by exhaustive search leaves 29 references to 12 items pointing upward, and those 12 items move to core.
- **Loop:** the same 0.9 to 1.4 s lib test for a domain edit.
- **Hook (estimate, not measured):** an edit to a low domain (economy, queries, messaging) re-lints every domain above it in series before the downstream chain, which I estimate adds 5 to 10 s.
- **Costs:** no traits between domains.
- **Why it loses:** a domain's tests cannot build a Supervisor. That needs every domain, and a domain above this one depends on it, so a dev-dependency on it would link a second copy of the crate under test, and its types would not match. 15.6k domain test lines would move to the top crate, and a domain edit followed by its own tests would rebuild that crate's test binary. Option D keeps those tests in place.

### Option F: Supervisor and actor run loop on top, domains below them

- **Asserts:** the Supervisor, the actor run loop and the dispatch match form the top crate and call domain functions directly. Domains reach the Supervisor through a `dyn` trait standing in for `SupervisorHandle` (42 methods today).
- **Costs:** no domain trait surface below the Supervisor, and the 33.6k core test lines stay in place.
- **Why it loses:**
  - The domain tests that build a Supervisor (15.6k lines) move to the top crate, as in Option E. So a domain edit is fast to compile but slow to test.
  - It splits ADR-049's core in two. `PerContextState`, `ClassSCell`, `ActorDeps` and `ContextCommand` sit below the domains, while the actor that owns them sits above.
  - The task this record answers asks for the mailbox and dispatch to stay in one core crate, with domain handlers attached to it.

### Option G: a generic `Supervisor<H: Domains>` in place of trait objects

- **Asserts:** core is generic over a type that supplies every domain, and the assembly crate names the concrete type.
- **Costs:** no `Box` per call.
- **Why it loses:**
  - The type parameter spreads to every public type that holds a Supervisor or a handle: `SupervisorHandle`, `ActorDeps`, `ContextActor`, every bridge's `CoreFields`, and every SDK signature built on them.
  - Monomorphization moves the codegen of core's generic code into the assembly crate, so a core edit recompiles the assembly crate too, and the split saves less.
  - ADR-049 Decision 7 already erases provider traits as `Arc<dyn …>` for the same reason.

## Decision

Option D.

### 1. Crate graph

```
scp-protocol, scp-crypto, scp-platform, scp-mls, ...   (unchanged)
        ↑
scp-runtime-types        40 leaf modules
        ↑
scp-runtime-core         actor, mailbox, dispatch hub, Supervisor, identity actors,
                         store, sync, trust, shared domain types, DomainHandlers + 13 traits
        ↑
scp-runtime-{economy, queries, messaging, lifecycle, ttl-close, governance, broadcast,
             outlets, push, lifecycle-control, saga, standing, trust-recovery}
                         13 siblings; each depends on types and core only
        ↑
scp-runtime              assembly: builds DomainHandlers; holds tests that build a
                         Supervisor from core alone; examples
        ↑
scp-core, scp-transport, scp-node, scp-ffi*, scp-testing, ...   (dependents today)
```

The rule a reviewer checks: a crate named `scp-runtime-<domain>` lists no other `scp-runtime-<domain>` crate under `[dependencies]`. It may list them under `[dev-dependencies]`.

### 2. Which modules move where

| Destination | Source under `crates/scp-runtime/src/` |
|---|---|
| `scp-runtime-types` | `context/config`, `context/policy`, `context/invitation_helpers`, `context/governance` (with `governance/timeout`), `context/outlets/signer`, `context/outlets/stream`, `context/supervisor/saga_journal`, `context/actor/sequence`, `crypto/access_keys` (with `lifecycle`, `wire`), `crypto/sender_keys` (with `key_protocol`), `crypto/ucan` (with `mint`), `crypto/mls/attestation_verification`, `crypto/mls/backend`, `crypto/mls/production_backend`, `crypto/mls/storage_adapter`, `discovery` (all six modules), `economy` (all five modules), `envelope/pseudonym`, `identity/blocking`, `identity/custody_migration`, `identity/scpid`, `metrics`, `provenance`, `sync/weeks_offline`, `trust/participation_service`, `well_known`. These are the 40 modules cut 1 moved and compiled. |
| `scp-runtime-<domain>` | `context/<domain>_helpers.rs` → `src/helpers.rs`; `context/<domain>_logic.rs` → `src/logic.rs` where it exists; `context/actor/handlers/<domain>.rs` → `src/handler.rs`; that domain's `*_tests.rs` files beside them. The 13 domains are the 13 `ContextCommand` sub-enum handlers: messaging, lifecycle, governance, broadcast, economy, trust_recovery, standing, ttl_close, outlets, queries, push, saga, lifecycle_control. |
| `scp-runtime-core` | Every other module. This includes `context/actor/` (minus handlers), `context/supervisor/`, `context/outlets/` (minus `signer` and `stream`), `store`, `sync`, `trust`, `identity` (minus the three above), `push`, `crypto/mls/provider`, and the 28 types and constants in the Appendix that two or more crates name. |
| `scp-runtime` (assembly) | `lib.rs` with one function that builds `DomainHandlers`, the examples, `tests/` as today, and the core test modules that build a Supervisor, moved to `tests/<original module path>.rs`. |

**Rule for each cross-boundary function in the Appendix.** If it reads or writes only state that core owns and calls no domain function, it moves to core. Otherwise it becomes a method on its domain's trait. Function names point toward the first group, for example the twelve `messaging_helpers` snapshot and persist functions and `standing_helpers::generate_standing_context_id`. A name is only an indicator; the implementing story reads each body to decide.

**Core's `shared/` modules.** A function or type that moves to core under the rule above, and that one domain's file held on `main`, sits in `core/context/shared/<domain>.rs`, which takes its name from that domain. A `shared/` file admits an item only under the same rule: the item reads or writes only state that core owns and calls no domain function, through `domains.<d>` or otherwise. The file name records where the item came from. Core owns every item in it, and a domain crate calls it as it calls any other core item. An item that fails the rule becomes a trait method of its domain instead.

**Rule for generic functions.** A function generic over closures or types cannot be a `dyn` trait method. Such a function moves to core when core calls it; `outlets_helpers::invoke_outlet_with_economy` is the one case today.

### 3. How handlers attach: `DomainHandlers`

Core defines one trait per domain and one struct that holds one implementation of each:

```rust
// scp-runtime-core
#[async_trait]
pub trait GovernanceDomain: Send + Sync {
    async fn dispatch(&self, cell: &mut ClassSCell, deps: &ActorDeps, cmd: GovernanceCommand) -> Outcome<()>;
    async fn evaluate_governance_timeouts(&self, state: &mut PerContextState, deps: &ActorDeps);
    // one method per governance function core or another domain calls (Appendix)
}

pub struct DomainHandlers {
    pub governance: Arc<dyn GovernanceDomain>,
    pub messaging: Arc<dyn MessagingDomain>,
    // one required field per domain, 13 in all
}
```

- **Injection through the initializer.** The Supervisor's initializer takes `domains: DomainHandlers` as a required field. The Supervisor stores it once, and each `ActorDeps` carries an `Arc` clone of it. No registry, map, lookup, fallback or global exists. A missing domain is a compile error in the struct literal, so no runtime check is needed.
- **The assembly crate builds the struct.** `scp_runtime::domain_handlers()` returns `DomainHandlers { governance: Arc::new(scp_runtime_governance::Governance), … }`. Each domain crate defines one field-less struct that implements its trait by delegating to its own `pub(crate)` functions.
- **Each bridge passes it in.** Each bridge's construction passes `scp_runtime::domain_handlers()` into the Supervisor initializer. The SDK construction surface (ADR-052) does not change, because this field is internal to the bridge and is not a caller's choice.
- **The dispatch hub stays in core.** `ContextActor::dispatch_state` keeps its exhaustive `match` over `ContextCommand`, and each arm becomes `deps.domains.<domain>.dispatch(cell, deps, sub).await`. A new `ContextCommand` variant without an arm is still a compile error in core. A new domain without a field is still a compile error in the assembly crate.
- **Every cross-crate call goes through a trait.** Core reaches a domain as `self.domains.<domain>.<method>(…)` in the Supervisor or as `deps.domains.<domain>.<method>(…)` in the actor. A domain reaches another domain the same way through `deps`. No crate names a sibling domain crate in production code.
- **Domain functions keep their visibility.** A domain's functions stay `pub(crate)`. Only the trait implementation is public, and its methods sit inside an `impl` block.
- **Trait methods keep their function names, except one.** Each Appendix function that becomes a trait method keeps its name and, except under the next rule, its parameters after `&self`. The lifecycle trait names its import method `import_context_from_export`, because the call invariant `snapshot-validation-on-import` in `.docs/standards/sdk-capability-matrix.json` requires every runtime function named `import_context` to call `validate_export_for_import` in its own body. A trait wrapper named `import_context` that delegates to the lifecycle crate's `helpers::import_context` would match that rule and fail it. The rule keeps its two callers: the lifecycle crate's `helpers::import_context` and `Supervisor::import_context`. `EconomyDomain::enforce_economy` keeps its name, because the `economy-enforced-on-send-path` invariant matches the callee by its last path segment.
- **A trait method may take one request struct.** When the parameters after `&self` would exceed clippy's `too_many_arguments` bound, the method takes one flat named-field struct that core defines beside the trait, in place of the positional list. The struct follows ADR-052, the unified construction pattern: named public fields and no builder. The repository forbids silencing a clippy lint with `#[allow]`, so `#[allow(clippy::too_many_arguments)]` on a trait method is not an option. Two methods take one: `LifecycleDomain::create_context` takes `CreateContextRequest`, and `OutletsDomain::reserve_outlet_economy` takes `ReserveOutletEconomyRequest`. The orchestrator decided this rule on 2026-11-04.

### 4. Visibility of core items that domain crates use

Domain code names about 29 core free functions that are restricted today (`pub(crate)`, `pub(super)` or `pub(in …)`), matched by name, so the exact count is the implementing story's to confirm. Examples are `state::emit_event_into`, `state::require_active`, `outlets::invoke::authorize_outlet_payment` and `ttl::apply_ttl_terminal_transition`. Each becomes `pub` under one rule:

- **Mutating items require a core capability.** A core item that mutates context state becomes a method of a type whose constructor stays private to core: `ClassSCell`, `ActorDeps`, `PerContextState` or `SupervisorHandle`. Core hands those values only to a domain trait method. Code outside core and the domain crates, an FFI bridge for example, can never obtain one, so the method is reachable from exactly the code that reached it before.
- **Pure items may become free functions.** A pure item, one that reads only its arguments and writes nothing, may become a `pub` free function.

**What the seal covers.** `SupervisorHandle::wrap`, `ClassSCell::new`, the restricted fields of `PerContextState` and the `owned_identity` field of `ActorDeps` stay restricted to core, so no code outside core can build any of the four capability values. An operation over the whole Supervisor, such as the shutdown sweep or the restore of every persisted context at start, reads and writes only core state, so under §2's rule it lives in core, and no domain trait method receives a `Supervisor`.

**Trust boundary of injection.** `DomainHandlers` has public fields and core does not seal the 13 traits, so the code that assembles a Supervisor chooses every domain implementation. Each implementation receives `&mut ClassSCell` and `&ActorDeps` with every command, and through `ActorDeps::my_wrapping_key` it can run key agreement with the wrapping key of the identity that owns the context. The code that assembles `DomainHandlers` is therefore trusted in-process code, with every identity's wrapping-key agreement: today that is `scp_runtime::domain_handlers()` and each bridge or application that calls a Supervisor initializer. The seal in this section holds against all other code: code that holds a Supervisor or links core, an FFI bridge function for example, but did not assemble that Supervisor can neither obtain a capability value nor call a restricted item.

`check-cross-layer.sh` does not flag a method inside an `impl` block. So under this rule the split adds no `pub fn` line that needs an FFI export, except the pure helpers that move to core; §Enforcement files lists that gate's change.

### 5. Tests

- **Domain tests stay in place.** A domain crate's tests that build a Supervisor stay where they are. Each domain crate carries one test helper that builds `DomainHandlers` from `crate::<Domain>` and its 12 siblings, which it lists as dev-dependencies. The required fields keep the 13 helpers from drifting.
- **Core tests that build a Supervisor move to the assembly crate.** They are 33.6k lines, and they move to `crates/scp-runtime/tests/`, one test target per original module, so each target recompiles alone. A core item that such a test reaches and that is restricted today becomes `pub` under `#[cfg(feature = "testing")]`. `check-shipped-feature-graph.sh` already keeps every `testing` feature off the shipped graph.
- **Other core tests stay in core.** These are the 18.1k lines that build no Supervisor.
- **Four context test files move to the messaging crate.** Each calls a messaging function that stays `pub(crate)` or `pub(super)`, so it moves beside that function into `crates/scp-runtime-messaging/src/`:
  - `context/pseudonym_rotation_runtime_tests.rs` builds a Supervisor and calls `encode_local_announcement`;
  - `context/agent_binding_pipeline_tests.rs` calls `verify_and_unwrap`, `send_message` and `build_encrypted_envelope_actor`;
  - `context/processed_commit_tests.rs` calls `decrypt_and_dispatch` and names `Dispatched`;
  - `context/sender_key_requeue_tests.rs` calls `deliver_incoming` and reaches governance through `deps.domains.governance`.

## How ADR-049 stays intact

- **Decision 1 (an actor owns its state by move):** `ContextActor`, `PerContextState` and the run loop stay in core. A domain receives `&mut ClassSCell` for one call, as today.
- **Decision 2 (the Supervisor is a plain struct):** the Supervisor stays in core with every field private. The lock order in `crates/scp-runtime/AGENTS.md` stays in core code: `bootstrap_spawn_lock` before `write_lock`, and `wrapping_key_loads[owner]` before `write_lock`. Domain code reaches `try_lock_bootstrap_spawn` only through `SupervisorHandle`, as today.
- **Decision 3 (capability reduction):** an actor and its domain code still hold a `SupervisorHandle`, never `Arc<Supervisor>`, and the handle still returns no `ContextActorHandle`.
- **Decision 5 (`OwnedIdentityDid`) and Decision 17 (`IdentityHandle`):** no domain file names either type today, so both stay in core with their constructors at their current visibility. The `compile_fail` doctest and the `#![deny]` guards in `supervisor/identity_capability.rs` move with the file unchanged.
  - Five domain sites read the `OwnedIdentityDid` value in the field `ActorDeps::owned_identity`, which is `pub(in crate::context)`, so a domain crate cannot reach it. The sites are `actor/handlers/lifecycle.rs:821`, `governance_helpers.rs:3115`, `lifecycle_helpers.rs:1809`, `messaging_helpers.rs:3376` and `trust_recovery_helpers.rs:249`. Each one calls `deps.supervisor.my_wrapping_key(&deps.owned_identity)`.
  - Core adds `pub fn my_wrapping_key(&self) -> Result<Arc<IdentityWrappingKey>, ContextError>` to `ActorDeps` in `actor/deps.rs`. Its body is `self.supervisor.my_wrapping_key(&self.owned_identity)`, and the five sites call `deps.my_wrapping_key()`.
  - `owned_identity` keeps its visibility, and `SupervisorHandle::my_wrapping_key` stays `pub(in crate::context)`. A domain crate can therefore load the wrapping key only of the identity that owns its actor, and still cannot name or construct an `OwnedIdentityDid`.
- **Decision 7 (`Send` providers as `Arc<dyn …>`):** the 13 domain traits follow the same form, `#[async_trait]` with a `Send + Sync` supertrait. A domain call adds one `Box` per call. Every handler `dispatch` already boxes its future with `Box::pin` to stay under clippy's `large_futures` bound, so the dispatch path gains one indirection and no new allocation class.
- **Decision 9 (Class-S persistence fails closed):** `ClassSCell` stays in core with no `DerefMut`, and its `commit_class_s_*` combinators become `pub` methods. A domain still mutates Class-S state only through them, because only core constructs the cell. The `subsume` caller allowlist test changes as §Enforcement files states.
- **Decision 10 (no panics on the actor task):** `check-handler-no-panic.sh` keeps its three scopes over the new paths, as §Enforcement files states.
- **Decision 12 (lock-free reads):** `crates/scp-runtime/clippy.toml` is copied into each new crate, and a new gate keeps the copies byte-identical, as §Enforcement files states.
- **Decision 14 (performance):** the implementing PR ran `perf_baseline` on `main` and on the split branch on one machine before it deleted the harness, and its description reports both runs. ADR-049 Decision 14, as amended 2026-11-03, names no harness and no merge gate.
- **Decision 16 (task drain and `Weak<Supervisor>`):** the task tracker and the closed flag stay in the Supervisor in core. Domain code spawns through `ActorDeps` as today.

## Consequences

- **Faster domain and types edits.** A domain edit's lib test rebuilds in 0.9 to 1.4 s against 7.2 to 9.5 s today. A types edit's rebuilds in 1.2 to 1.7 s against 5.2 s. Together these are 36% of the last 60 days' file changes.
- **Core edits change little.** They keep a rebuild I estimate at 4 to 5 s against 5.2 to 8.4 s today. Running a moved core test after a core edit also rebuilds that test target in the assembly crate.
- **The hook.** Under the hook these figures were measured with, the hook drops from 22.9 s to 13.7 s for a domain edit and stays at 20.2 to 20.7 s for core and types edits. The remaining ≈13 s is the re-lint of downstream crates. The hook now lints only the members a commit changes, so a domain edit's hook run lints that domain crate and leaves its dependents to CI. The implementing PR re-measures the hook and the lib-test rebuilds on `main` and on the split branch, and its description reports both.
- **Import updates.** The 89 `.rs` files and 12 manifests outside `crates/scp-runtime` that name a moved path import it from the owning crate. The assembly crate re-exports nothing, because ADR-057's amendment forbids shim re-exports of moved code.
- **Cross-domain calls need core.** A new call from one domain to another adds a trait method in core, which is a core edit.
- **Release.** `release.yml` publishes 15 more crates in dependency order: types, then core, then the 13 domains, then `scp-runtime`.
- **Two more gates.** The clippy-config gate and the `testing`-feature coverage rule in §Enforcement files.

## Enforcement files

Alec approved every change below on 2026-11-03, as the Status line states. **P** marks a file the root `AGENTS.md` lists as a protected enforcement file. Abbreviations: `core/` is `crates/scp-runtime-core/src/`, `types/` is `crates/scp-runtime-types/src/`, and `<d>/` is `crates/scp-runtime-<domain>/src/`.

### Path updates that keep each assertion as strong as today

| File | Today | Change |
|---|---|---|
| **P** `crates/scp-testing/tests/integration/pipeline_wiring.rs`, `MANAGER_SRC` (lines 31-45) | Concatenates 3 `*_logic.rs` and 10 `*_helpers.rs` files and asserts pipeline steps in the result | Each `include_str!` points at `<d>/logic.rs` or `<d>/helpers.rs`. `MANAGER_SRC` also adds `core/context/snapshot.rs`, `core/context/push_routes.rs` and every other core file that receives a function from a helper file and that an assertion over `MANAGER_SRC` names. Without those files, each assertion that names a function moved to core fails |
| **P** same, the constants `PROVIDER_SRC`, `STATE_SRC`, `SUPERVISOR_SRC`, `OUTLETS_INVOKE_SRC`, `ACTOR_MOD_SRC`, `PSEUDONYM_ROTATION_SRC`, `PUSH_REGISTRAR_SRC`, `LEDGER_SRC` (lines 47-288) | Assert against those core files | The same relative path under `core/` |
| **P** same, `HANDLERS_{MESSAGING,BROADCAST,PUSH,QUERIES}_SRC`, `PUSH_HELPERS_SRC` (lines 193-239) | Assert against handler files | `<d>/handler.rs`, and `crates/scp-runtime-push/src/helpers.rs` |
| **P** same, the local `include_str!` calls at lines 1147, 2678, 2709, 2726, 3273, 4671, 5062, 8755-8804, 9630 | Single-file assertions | Governance, lifecycle and trust-recovery files go to `<d>/handler.rs` or `<d>/helpers.rs`. `actor/state.rs`, `supervisor/handle.rs` and `supervisor.rs` go to `core/` |
| **P** same, lines 1506-1573 and 4301-4566 | `SUPERVISOR_SRC` contains the bodies of `dispatch_lifecycle_direct` and `dispatch_push_command`, which call domain helpers by path | The Supervisor methods stay in `core/context/supervisor/supervisor.rs`. Each assertion of `lifecycle_helpers::<f>(` becomes two: `supervisor.rs` contains `domains.lifecycle.<f>(`, and `crates/scp-runtime-lifecycle/src/lib.rs` implements `<f>` by calling `helpers::<f>(`. Two hops, each asserted, keep the chain as strong as one |
| **P** same, `no_actor_turn_waits_on_the_bootstrap_spawn_lock` (line 9479) | A syn scan resolves calls by name over `crates/scp-runtime` production files | The scan reads the union of `crates/scp-runtime*/src`. A call through `domains.<d>.<f>` resolves to the implementing method in `<d>/lib.rs`, so the call graph is the same one. The adapter files become `core/context/outlets/stream_{settlement,counter}_adapter.rs` |
| **P** `scripts/check-cross-layer.sh` (lines 50-53) | A new `pub fn` in `scp-protocol/src` or `scp-runtime/src` needs an FFI export | The pathspec becomes `':(glob)crates/scp-runtime*/src/**/*.rs'`. Without this change, a moved file falls outside the pathspec and the gate passes on every future `pub fn` in it |
| **P** `scripts/check-saga-gating-granularity.sh` (lines 133, 135) | Items P1 to P5 in `supervisor.rs` | `SUPERVISOR_REL` becomes `crates/scp-runtime-core/src/context/supervisor/supervisor.rs`. All four items stay in that file |
| **P** `scripts/check-call-invariants.py` (lines 109, 829-831) | `BRIDGE_ROOTS["runtime"]` is `crates/scp-runtime/src` | A list of the 16 runtime source roots. See the next table for the added assertion this needs |
| **P** `.docs/standards/sdk-capability-matrix.json`, `code_sites` (lines 2565, 2566, 2584, 2585) | `messaging_helpers.rs:211`, `economy_logic.rs:313`, `lifecycle_helpers.rs:1324`, `supervisor.rs:3750` | The new path and line of the same code |
| **P** `scripts/check-shipped-feature-graph.sh`, `PERMITTED_CRATES` and the feature allowlist (lines 284, 375) | Closed allowlists naming `scp-runtime` | Add the 15 crates, and a `/default` row for each that declares features. The gate fails closed until then |
| **P** same, `NULLIFIER_CONTROL_FEATURES` (lines 567-606) and fixtures (lines 2375-2383) | Lists every test-only feature | Add `<crate>/testing` for each new crate that declares it, and `scp-runtime-core/{allow_unencrypted_storage, saga-witness-test-mint, outlet-capability-test-grant}`. Add fixtures for them |
| **P** root `AGENTS.md`, Integration checklist item 1 | `dispatch_*` → mailbox → `handlers/<domain>.rs` → `<domain>_helpers.rs`; `create_context`, `import_context` and `restore_context` call `lifecycle_helpers` directly | `dispatch_*` → mailbox → `core/context/actor/mod.rs` → `deps.domains.<d>.dispatch` → `<d>/handler.rs` → `<d>/helpers.rs`; the three bootstrap methods call `domains.lifecycle.<f>` from the Supervisor |
| `crates/scp-runtime/src/context/actor/class_s.rs`, `subsume_caller_allowlist_is_bounded` (lines 4944, 4949) | A closed list of (file, count) pairs for `.subsume(`, read from files within one crate | The test scans every `crates/scp-runtime*/src` file for `.subsume(` and compares against the closed list. Today the compiler bounds `subsume` to the crate, and the list bounds callers within it. After the move `subsume` is `pub`, so the scan of every runtime crate takes over the compiler's bound. The scan lives in `crates/scp-testing/tests/subsume_caller_allowlist.rs`, outside every runtime crate, so it reads files across crates without one crate's test reaching into its siblings |
| `scripts/check-handler-no-panic.sh` (lines 117, 360, 389, 976) | Three scopes: `handlers/`, the hub `actor/mod.rs`, and the helper layer under `src/context` with a 5,000-line floor | Handlers: the 13 `<d>/handler.rs` files and `core/context/actor/handlers/mod.rs` if it survives. Hub: `core/context/actor/mod.rs`. Helper layer: `core/context`, `types/context`, and every `<d>/{helpers,logic,handler,lib}.rs`, with the floor summed over the union. The script gains multi-root scanning |
| `scripts/check-deleted-primitives.sh` (lines 106-127) | 13 rows, each scoped to `crates/scp-runtime` or `crates/scp-runtime/src/crypto` | Each row's scope becomes every `crates/scp-runtime*` directory, through a loop in the script. The `crypto` row covers `types/crypto` and `core/crypto` |
| `ratchet/block-in-place-count.json` | Per-file counts and a summary of 14 for `scp-runtime` | Rekey `context/lifecycle_helpers.rs` (2) to `crates/scp-runtime-lifecycle/src/helpers.rs`. Rekey `identity/recovery.rs` (0), `store/context.rs` (0) and `store/trust.rs` (6) under core. Replace the summary with one entry per crate. The counts do not change |
| `scripts/check-test-vectors-p256.py` (lines 190, 194) | Golden hex literals must be in two named files | `crates/scp-runtime-messaging/src/pseudonym_rotation_runtime_tests.rs` and `types/crypto/access_keys/wire.rs`. The golden hex values do not change |
| `scripts/hooks/pre-commit` (line 164), `scripts/tests/pre-commit-clippy-scope/run-tests.sh` (line 97, `ALL_FEATURES`) | `CLIPPY_FEATURES` names `scp-runtime/testing`. The hook lints only the members a commit changes and keeps only the `CLIPPY_FEATURES` entries whose package it selects | Add `scp-runtime-types/testing`, `scp-runtime-core/testing`, `scp-runtime-core/saga-witness-test-mint` and the 13 `scp-runtime-<d>/testing`. Otherwise a commit that touches only a domain crate lints it without `testing`, while CI lints it with `testing` through feature unification. `run-tests.sh` adds a case in which an edit to `crates/scp-runtime-governance/src/lib.rs` selects `-p scp-runtime-governance --features scp-runtime-governance/testing` |
| `.github/workflows/ci.yml` (lines 599, 1966), `cache-warm.yml` (line 91), `scripts/tests/ci-gate/ci_gate_selftest.py` (lines 8259-8267) | The fuzz path filter and the runtime nextest shard `-p scp-runtime -p scp-core` | Add `'crates/scp-runtime-*/**'` to the filter and `-p` for the 15 crates to the shard. `check-test-shard-features.py` requires each member in exactly one shard |
| `Cargo.toml` (lines 20, 103), `crates/scp-runtime/Cargo.toml` features, `release.yml` (lines 184, 212, 620-623) | Workspace members, features and publish order | Add the 15 crates with `[lints] workspace = true`. Each `scp-runtime` feature forwards to the same feature on every new crate that declares it, so the CI feature strings keep reaching the moved code. Publish in dependency order |
| `crates/scp-runtime/AGENTS.md`, `.claude/agents/{completionist,black-hat,bug-catcher,security-reviewer,performance-optimizer,architect}.md` | Name runtime paths and the handler route | Move the invariants to `crates/scp-runtime-core/AGENTS.md`, and give each domain crate a one-line `AGENTS.md` that points there |

These files need no change, because they find new crates or name no moved path: `check-protocol-deps.sh`, `check-no-mutable-globals.sh`, `check-no-shim-reexports.sh`, `check-no-fallback-registry.sh`, `ratchet/once-lock-count.json`, `pure-helpers-allowlist.txt`, `check-block-in-place.py`, `check-examples-compile.sh`, `ffi_conformance.rs`, `call-invariants-baseline.json` and `deny.toml`.

### Assertions to add, because a path update alone would weaken the check

| File | Why a path update is not enough | Added assertion |
|---|---|---|
| **P** `scripts/check-call-invariants.py` | `crates/scp-runtime/src` still exists as the assembly crate. With only that root, the two runtime rules (`economy-enforced-on-send-path`, `snapshot-validation-on-import`) find no caller that matches and pass with no violation | A rule whose caller pattern matches zero production functions under a bridge root it applies to fails. This assertion fails on `main` today: `callback-custody-record-store-at-create` applies to `pyo3` with the caller pattern `^(build_key_custody\|decide_custody_for_create)$`, and the pyo3 bridge renamed `build_key_custody` to `callback_custody` (`crates/scp-ffi/src/identity.rs`). The same commit changes that pattern to `^(callback_custody\|decide_custody_for_create)$` and its code site in `.docs/standards/sdk-capability-matrix.json` to `callback_custody → callback_registry → create_records`. The rule id does not change, so the baseline digest does not change |
| New: `scripts/check-runtime-clippy-config.sh` | Clippy reads the nearest `clippy.toml` and has no include. A new crate without a copy falls back to the root `.clippy.toml`, which lacks ADR-049 Decision 12's `disallowed-types` | Every `crates/scp-runtime*/clippy.toml` exists and matches `crates/scp-runtime-core/clippy.toml` byte for byte |
| **P** `scripts/check-protocol-deps.sh`, a new manifest check | Option D depends on domain crates being siblings, and Cargo accepts a domain-to-domain dependency without complaint | No `crates/scp-runtime-<domain>/Cargo.toml` lists another `scp-runtime-<domain>` under `[dependencies]` |
| **P** `scripts/check-shipped-feature-graph.sh` | `NULLIFIER_CONTROL_FEATURES` knows only the names it lists, so a `testing` feature added to a new runtime crate later is unlisted | Every feature named `testing`, `allow_unencrypted_storage`, `saga-witness-test-mint` or `outlet-capability-test-grant` on any `scp-runtime*` crate appears in the list |

## Appendix: functions and types named across a domain boundary

The bracket after each function names who calls it: `core`, the calling domain, or `core tests`. Each function tagged `core` or with a domain either moves to core or becomes a trait method under §Decision item 2's rule. A function tagged `core tests` has no production caller outside its own domain: its only core caller sits in a `#[cfg(test)]` module, so it stays a `pub(crate)` function of its domain crate, and a test outside that crate reaches it through the crate's `testing`-gated `testing_access` module. Each type or constant moves to core.

- **broadcast**
  - Functions: `block_broadcast_subscriber` [core tests], `check_envelope_signed_by` [core], `dispatch` [core], `handle_broadcast_key_request` [core], `unblock_broadcast_subscriber` [core tests].
- **economy**
  - Functions: `authorize_paid_action_hold`, `authorize_paid_action_prepare`, `capture_and_verify_paid_action`, `commit_economy_ticket`, `emit_payment_received_event`, `enforce_economy`, `record_payment_receipt`, `rollback_economy_ticket_inline_view`, `void_paid_action` [all lifecycle, messaging]; `validate_spending_ucan_or_error` [outlets]; `dispatch` [core].
  - Types: `ContextRevocationChecker`, `EconomyTicket`, `EnforceEconomyRequest`, `KeyResolverDidResolver`, `OwnedAuthInputs`, `PaidActionAuthorization`.
- **governance**
  - Functions: `check_commit_fault` [lifecycle], `check_commit_fault_marker` [messaging], `dispatch` [core], `enforce_triggered_consequences` [messaging, outlets], `evaluate_governance_timeouts` [core], `event_log_entries_for_consequences` [outlets], `event_log_entries_for_consequences_after_side_effect` [lifecycle, messaging, outlets], `execute_propose_context_migration` [core tests], `execute_revoke` [core tests], `keep_broadcast_failure` [lifecycle, trust_recovery], `migration_destination_id` [core], `try_broadcast_commit` [lifecycle, trust_recovery].
  - Types: `CommitBroadcastBorrows`, `CommitMeta`, `EnforceConsequencesCtx`, `MigrationBootstrap`.
- **lifecycle**
  - Functions: `add_member_and_queue_distribution` [governance], `build_identity_assessment` [governance], `close_context` [core tests], `create_context` [core, governance], `derive_message_pricing` [core], `dispatch` [core], `drain_and_deliver_sender_keys` [governance, messaging], `flush_all_contexts` [core], `fold_rollback_failure` [core, governance], `import_context` [core], `normalize_relay_urls` [core], `persist_first_state` [core], `restore_all_contexts` [core], `restore_context` [core], `restore_crypto_state_with_floor_guard` [core, lifecycle_control], `retry_pending_sender_key_rotation` [governance], `rotate_sender_key_and_distribute` [governance], `shutdown_all_contexts` [core], `verify_scp_context_binding` [core].
  - Types: `DistributionScope`, `FirstStateRollback`, `SpawnedContext`.
- **lifecycle_control**
  - Functions: `dispatch` [core].
- **messaging**
  - Functions: `build_encrypted_envelope_actor` [core], `build_inner_wire` [core], `build_snapshot_for_persist` [lifecycle, saga], `build_snapshot_from_state` [core, lifecycle], `caveat_counters_snapshot` [core], `commit_send_nonce_token_on_abort` [lifecycle], `decrypt_and_dispatch` [core tests], `dispatch` [core], `finalize_send` [core tests], `mirror_forward_local_sender_epoch` [governance, lifecycle], `persist_snapshot_fail_closed` [saga], `persist_state_best_effort` [broadcast, core, governance, lifecycle, saga, trust_recovery, ttl_close], `persist_state_fail_closed` [core], `saga_pending_snapshot` [core], `stream_reservations_snapshot` [core], `welcome_snapshot_crypto_is_durable` [core], `xctx_caller_reservations_snapshot` [core], `xctx_committed_invocations_snapshot` [core], `xctx_committed_outputs_snapshot` [core], `xctx_committed_stream_outputs_snapshot` [core], `xctx_nonce_dedup_snapshot` [core].
  - Types: `DeliverOutcome`, `Dispatched`.
- **outlets**
  - Functions: `authorize_and_capture_stream_billed` [core], `build_stream_post_input_hook` [core], `dispatch` [core], `invoke_outlet_with_economy` [core], `reserve_error_to_open_rejection` [core], `reserve_outlet_economy` [saga], `reverse_caller_reservation_record` [saga], `rollback_outlet_economy` [saga], `rollback_outlet_economy_generation_checked` [saga], `settle_outlet_economy` [saga].
  - Types: `InvocationCaveatBinding`, `ManagedOutletInvocationOutput`, `OutletEconomyReservation`, `OutletEconomyTicket`, `OutletSettleOutcome`, `OutletSettleRequest`, `StreamEconomyReservation`.
- **push**
  - Functions: `dispatch` [core], `push_routes` [core].
  - Types: `ContextPushRoutes`, `ContextWakeTarget`.
- **queries**
  - Functions: `build_checkpoint`, `clear_needs_reconnect`, `force_create_checkpoint_fields`, `generate_context_access_key`, `restore_context_access_key`, `revoke_context_access_key` [lifecycle]; `compare_remote_checkpoint`, `create_checkpoint_if_due_view`, `force_create_checkpoint_view`, `report_degraded_mode` [messaging]; `dispatch`, `is_local_did`, `register_local_did` [core].
- **saga**
  - Functions: `dispatch` [core].
  - Constants: `SAGA_NONCE_DEDUP_TTL_SECS`.
- **standing**
  - Functions: `derive_standing_context_digest`, `dispatch`, `generate_standing_context_id` [core].
- **trust_recovery**
  - Functions: `create_governance_checkpoint`, `dispatch` [core].
- **ttl_close**
  - Functions: `convergent_ttl_deadline` [lifecycle], `dispatch` [core], `extend_ttl_deadline_and_record` [governance], `finalize_close` [core], `handle_ttl_expiry` [core], `reset_ttl_timer` [core tests].
  - Types and constants: `ConvergentDeadline`, `ExtensionLeaf`, `HANDLER_TIMEOUT`.

The counts and lists come from a scan of production code on `main` that strips comments and `#[cfg(test)]` modules and matches `<domain>_helpers::`, `<domain>_logic::` and `handlers::<domain>::` paths, including `use` lists. A call made through a glob import or a re-export is not counted, so the implementing story confirms each list against the compiler. The scan did not strip `supervisor.rs`'s `mod tests`, which opens at line 19356 under the `#[cfg(test)]` at line 19342 on `main`. The 2026-11-04 correction re-tagged the eight functions that this miss had tagged `core`.
