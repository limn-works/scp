---
name: adr049-contextinner-arcswap-sync-state
description: Review of ADR-049 Dec-12 ContextHandle RwLock<ContextInner>→ArcSwap making state()/transition_to()/try_read_state() sync; sole gap = standalone template missed
metadata:
  type: project
---

Review of branch `chore/adr049-contextinner-arcswap` (4de63ce09) vs origin/main (2e8a08459).
ContextHandle.state()/transition_to() async→sync (ArcSwap<ContextState> replaces
RwLock<ContextInner>); try_read_state() kept (sig unchanged, now always Some).

VERDICT: INCOMPLETE (narrow). Workspace propagation is 100% complete — a full branch-wide
`git grep` found ZERO stale `.state().await` and only ONE stale `transition_to(...).await`.

**Why:** the SOLE gap is a standalone-workspace consumer the coder never reached:
`templates/cross-context-bridge/src/main.rs:54` — `handle.transition_to(&ContextState::Active).await?`
on `scp_core::context::ContextHandle`. Won't compile (Result is not a Future). The template
Cargo.toml declares its own empty `[workspace]`, so it is NOT a root-workspace member and NO
CI workflow builds templates/ (verified build-matrix.yml/docs.yml/release.yml) — so
`cargo build --workspace` and CI never catch it. Identical to origin/main (was correct there
when the method was async). Fix = drop the single `.await`.

**How to apply:** on any Rust signature change (async→sync, param add) always sweep
`templates/`, `scaffolds/`, and top-level `examples/`/`tests/` — anything with its own
`[workspace]` in Cargo.toml is invisible to workspace CI. `git grep <pat> <branch> -- '*.rs'`
over the WHOLE tree, not just changed files. This exactly matches the recurring
[[adr057-t1c-dht-extract]] lesson (scaffolds/templates repoints are the highest-yield miss
on refactor slices).

Everything else COMPLETE & verified:
- scp-runtime core: read_context_state helper deleted (was the async wrapper); all sites sync.
- FFI: pyo3 (scp-ffi/src/context.rs), napi (context.rs:4242), uniffi (bridge.rs) all dropped
  .await. WASM: zero refs (bridge removed per ADR-055) = N/A. FFI-wrapper .state()/.unwrap()
  sites (return Result<String>) are the bridge's OWN methods, unaffected — do not confuse with
  core ContextHandle::state().
- SDK wrappers py/ts/swift/kt: internal sig change, no surface impact; .docs/scaffold/kotlin.md
  handle.state() is UniFFI-binding-level. N/A.
- examples/context.rs+tools.rs, all integration tests (conformance/context_lifecycle/phase2/
  persistence/network_simulation): updated in-diff.
- Docs: README.md, ADR-049 §10 ("cheap cached per-handle state getter" @line247), clippy.toml
  all consistent. check-deleted-primitives.sh change is ADDITIVE (activates RwLock<ContextInner>
  ban) — legit coverage expansion, not a weakening.

LOW observation (not a blocker, out of one-way-flow): `.claude/agents/bug-catcher.md:46` +
`black-hat.md:43` still describe "ContextHandle RwLock" and advise "handle.state().await inside
held Mutex deadlocks — use try_read_state() instead"; now stale (RwLock gone, state() sync &
infallible). Agent-guidance files, not ADR/spec.

---
ROUND 2 (arcswap tip 427b01e1f, commits 82673db6d/57dc18f03/427b01e1f) — VERDICT: COMPLETE.
7 fixes all verified across every layer. NOTE: working-tree HEAD was a DIFFERENT branch
(ceiling work 1620de983); named commits are NOT in HEAD — must review via `git grep <rev>`/
`git show <rev>:<file>` against tip 427b01e1f, never the working tree.
- FIX4: `try_read_state` DELETED (mod.rs); branch-wide grep = ZERO refs (crates/bindings/
  templates/examples). 8 non-test + 4 test-file migration sites all preserved semantics —
  `.ok_or(ContextNotActive)?`, `.unwrap_or(Active)`, `.is_some_and(matches!)` all correctly
  collapsed to infallible `state()`; the removed None/contended branches were genuine dead
  cases (ArcSwap load can't fail). BONUS beyond round-1 scope: `transition_to` upgraded blind
  load-store → compare_and_swap retry loop (std::ptr::eq(previous,current) idiom) because the
  cell is genuinely MULTI-WRITER (actor loop + off-actor napi context_finalize_close_on clone).
- FIX3: template `.await` gone (fn de-async'd, both callers updated); the 8 other arity errors
  correctly left for #2046, not re-flagged.
- FIX2: §13 test `context_handle_cas_stress` in tests/shuttle_actor.rs is REAL & always-on —
  under `#[cfg(not(feature="shuttle"))]` (default), 2 un-#[ignore]d #[test]s (2000-iter 4-writer+
  reader race asserting exactly-one-winner + no-torn-read; + rejected-transition no-op). Target
  is AUTO-DISCOVERED (no [[test]] entry / no required-features), runs on plain cargo test.
- FIX5/FIX7: ADR-049 §Decision-12 + bug-catcher.md:46 + black-hat.md:43 all corrected — now
  say ArcSwap/CAS, explicitly "There is no try_read_state(); call state() directly", RwLock
  dropped from lock-count. Accurate, not just changed.
- Cross-layer (item 5): FFI/SDK never referenced try_read_state (ZERO in scp-ffi/+bindings/).
  napi context.rs:108 + uniffi bridge.rs:2944 keep their OWN separate `Mutex<ContextState>`
  snapshot caches (per ADR-049 §12a) — distinct from ContextHandle's ArcSwap, correctly
  untouched. clippy.toml RwLock<ContextInner> hits = the ADDITIVE grep-ban comments.
RESIDUAL non-blocker (out of scope, NOT one of the 7): `.claude/agent-memory/bug-catcher/
MEMORY.md:110` historical note still cites `try_read_state()` — bug-catcher's OWN scratch
memory, not a system-of-record artifact; that agent curates it.
