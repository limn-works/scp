# Phase 7 Architecture Decision Records — Actor-Per-Context

**Date:** April 16, 2026
**Phase goal:** Convert ContextManager to an actor-per-context architecture where each context runs as an independent async task.

---

## ADR-046: Convert Provider Traits to Async (PR 0.1)

**Status:** Decided
**Date:** April 2026

### Context

The actor-per-context redesign requires that provider trait methods (`ContextCryptoProvider`, `ContextTransportProvider`, `ContextPersistence`) be async, because in the target architecture every operation on a context crosses a tokio channel boundary to the owning actor task.

PR 0.1 is the mechanical prerequisite: convert all provider trait methods from synchronous to async without changing runtime behavior.

### Decision

1. **Use `#[async_trait]`, not RPITIT (return-position `impl Trait` in traits).** These traits are used as `dyn` objects (`Box<dyn ContextCryptoProvider>`, `Box<dyn ContextPersistence>`). Rust's `async fn` in traits does not support `dyn` dispatch; `#[async_trait]` desugars to `Pin<Box<dyn Future>>` which does.

2. **Add `async-trait` dependency to `scp-protocol`.** The `ContextCryptoProvider` trait lives in `scp-protocol`, which previously had zero async dependencies. `async-trait` is a proc-macro crate: it runs at compile time and adds zero runtime dependencies. It does not pull in tokio, futures, or any executor. `scp-protocol` remains executor-agnostic and continues to compile for `wasm32-unknown-unknown`.

3. **Keep `std::sync::Mutex` in `MlsCryptoProvider`.** The production crypto provider uses `std::sync::Mutex` for internal state. All lock scopes are synchronous (no `.await` between `lock()` and guard drop). The `#[async_trait]` wrapper is purely mechanical — the bodies remain sync. The `#[deny(clippy::await_holding_lock)]` lint on the impl block enforces this invariant at compile time. In PR 2.1, `MlsCryptoProvider` will be dissolved into per-context actors, eliminating the shared mutex entirely.

4. **`Box::pin` for recursive governance async.** `propose_governance_action` and `vote_on_proposal` may auto-execute approved proposals, creating a recursive async call chain. Rust requires explicit `Box::pin` for recursive async functions. The recursion depth is bounded at 2 levels (propose/vote -> execute -> dispatch; dispatch never calls back into execute). No runtime depth guard is needed.

### Consequences

- **Performance:** One heap allocation (`Box<dyn Future>`) per trait method call. Negligible compared to the MLS crypto operations inside (HPKE, AES-GCM, tree hashing).
- **Compile time:** `async-trait` proc-macro adds ~1s to `scp-protocol` compilation. Acceptable.
- **Migration path:** PR 0.1 is a no-behavior-change refactor. Subsequent PRs (1.x, 2.x) will introduce the actual actor architecture using these async boundaries.
- **WASM:** `scp-protocol` with `async-trait` continues to compile for `wasm32-unknown-unknown` (verified in CI).
