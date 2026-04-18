# ADR-048: SCP as First-Class Multi-Instance SDK Object

**Status:** Proposed
**Date:** 2026-04-18
**Phase:** Phase 4 remainder (issue #1549)
**Related:** ADR-021 (UniFFI Bridge), ADR-022 (Language Bindings), ADR-028 (Kotlin SDK), ADR-034 (WASM Constraints), ADR-043 (Scope Registration as Handle Convention, phase-3), ADR-046 (Bridge Parity Harness, sibling), ADR-047 (Bridge Symmetry Enforcement, sibling)

## Context

Phase 4a (PR #1628, augmented by #1672) consolidated dozens of per-identity singletons across the three non-WASM FFI bridges (PyO3, NAPI, UniFFI) into a single `BridgeInstance` struct accessed via `BRIDGE_INSTANCE: OnceLock<Arc<BridgeInstance>>`. The consolidation eliminated the worst of the cross-module state drift but left the `OnceLock` itself. Three structural problems followed from that choice:

1. **Tests must serialize.** `BRIDGE_LIFECYCLE_SERIAL` in `crates/scp-ffi/napi/src/runtime.rs:536` and the documented poisoning at `bindings/typescript/tests/lifecycle.test.ts:39-43` force process-wide serial execution of any test that touches bridge state. pytest-xdist, Gradle parallel tests, and XCTest concurrency are all forbidden. Builds are minutes slower than they need to be.
2. **Multi-identity and multi-relay coexistence are impossible.** One process, one bridge, one identity, one relay. A single Node hosting multiple SCP identities (the spec says nothing prohibiting this; operationally it is the natural shape of agent gateways and integration suites) cannot be expressed.
3. **Shutdown is terminal.** `BRIDGE_INSTANCE` is a `OnceLock` — once initialized, it cannot be replaced. `shutdown()` is infallible and one-shot. There is no mechanism to supply a timeout, cancel outstanding work cleanly, or tear down and restart within the same process.

The H1 chicken-and-egg pattern remains: callers write to process-global registries (identity_custody_registry, identity_link_attestation_registry) before `BridgeInstance::new()` runs, and the fresh empty registries installed by `new()` silently orphan those writes. Phase 4a patched the DID resolver case with a deferred setter; the rest of the pattern persists.

Phase 4b was collapsed into this remainder (per `scripts/close-reasons.md` and the 2026-04-17 audit). The remaining work — migrate every per-identity singleton, delete the fallback registries, delete the serialization mutex, and enable multi-instance coexistence — cannot be done in place under `OnceLock<Arc<BridgeInstance>>`. The `OnceLock` has to go.

## Decision

### 1. `SCP` is the first-class SDK-level opaque object in all four language SDKs

Every language SDK exposes a class named exactly `SCP`:

- Python: `scp_sdk.SCP` (`#[pyclass(name = "SCP")] PyScp`)
- TypeScript: `SCP` (`#[napi] class Scp`)
- Swift: `SCP` (`#[derive(uniffi::Object)] Scp`, renamed in UDL)
- Kotlin: `SCP` (same UniFFI object, Kotlin binding)

`SCP` wraps an owned `Arc<BridgeInstance>`. Instance state — ContextManager, identity registry, UCAN registry, MCP registries, transport manager, known-contexts cache, rate limiters, economy trackers, petname/handle/scope registries — lives on that instance. Operations that were previously free functions become methods on `SCP`:

```python
scp = scp_sdk.SCP()               # new
identity = scp.identity_create(…) # method, not module-level function
context = scp.context_create(…)
```

Pure protocol helpers that touch no registry (hashing, encoding, validation of shape-only inputs) stay as free functions.

The class is named after the protocol, not after internal plumbing. This matches the prevailing SDK convention (`OpenAI()`, `Anthropic()`, `Stripe()`) and avoids the collisions that `Node`, `Bridge`, or `Client` would create with existing application-layer classes (`server.py:125`, `server.ts:223`, `BridgeConnector` in spec §12).

### 2. `BridgeInstance` splits into three per-bridge concrete structs behind a shared trait

`BridgeInstance` stops being a single struct hosting four `Box<dyn Any>` slots. It refactors into:

- `PyBridgeInstance`, `NapiBridgeInstance`, `UniffiBridgeInstance` — concrete per-bridge structs holding typed fields for all bridge-specific registries (FFI_BRIDGE_STATE, MCP server/client registries, CREDENTIAL_STORE, identity_custody_registry, identity_link_attestation_registry, context_handle_registry, etc.).
- `BridgeInstanceCore` — a shared trait in `scp-ffi-common` exposing the bridge-agnostic fields (ContextManager, transport manager, known_contexts, rate_limiters, economy trackers, persistence, relay_url, shutdown_hooks, petname/handle/scope maps) and lifecycle helpers (`suspend()`, `resume()`, `shutdown(timeout)`, `check_ready()`).

Every shared helper in `scp-ffi-common` operates on `&dyn BridgeInstanceCore`. Per-bridge callers pass their concrete instance. The four `Box<dyn Any>` slots introduced in Phase 4a are removed. Type safety is compile-time; there are no runtime downcasts. This satisfies the CLAUDE.md rule "enforce mechanically — type system over documentation."

### 3. Default-instance façade remains as a sunset scaffold

`DEFAULT_BRIDGE_INSTANCE: OnceLock<Arc<{Py,Napi,Uniffi}BridgeInstance>>` (renamed from `BRIDGE_INSTANCE`; the concrete type varies per bridge — `PyBridgeInstance` in PyO3, `NapiBridgeInstance` in NAPI, `UniffiBridgeInstance` in UniFFI) stays in each bridge for one deprecation window. Existing free-function exports (`py_context_create`, `napi context_create`, UniFFI `context_create`) continue to work by forwarding to `SCP::default()`. Each forward emits a one-time deprecation warning per function name:

- Python: `warnings.warn(..., DeprecationWarning)`
- TypeScript: `console.warn(...)`
- Swift: `@available(*, deprecated, message: "Use SCP().contextCreate(…) instead")`
- Kotlin: `@Deprecated("Use SCP().contextCreate(…) instead")`

Removal target: **two release cycles after Phase 4 merge.** At removal, `DEFAULT_BRIDGE_INSTANCE` and every free-function forward are deleted. Backward-compat during the deprecation window is functional equivalence, not byte-identical behavior — `DeprecationWarning` is intentional.

A CI gate (`scripts/check-no-default-in-tests.sh`) rejects test files that call the free-function façade unless they carry the tag `SCP-DEFAULT-INSTANCE-OK: <reason>`. Production callers get the deprecation warning at runtime; test suites get the mechanical gate immediately.

### 4. Handle affinity enforced via `instance_id: u64`

Every `SCP` is assigned a monotonic `instance_id: u64` at construction. Every handle type (`ContextHandle`, `Identity`, `UcanToken`, `TransportManager`, `Message`, `MessageReceiver`, `RelayHandle`, `NodeHandle`, `DIDDocument`) carries the `instance_id` of its owning `SCP`. Every `SCP` method that takes a handle begins with a runtime check:

```rust
if handle.instance_id != self.instance_id {
    return Err(ScpError::HandleAffinity { ... });  // SCP-PERM-3030
}
```

Mismatch returns the new error code **`SCP-PERM-3030`**. The check is a single integer comparison at every FFI entry — noise-level overhead. A new gate script `scripts/check-handle-affinity.sh` verifies every handle-accepting FFI function contains the corresponding macro invocation.

Compile-time affinity via phantom lifetime was rejected: not expressible across Python / TypeScript / Swift / Kotlin. Runtime checks catch the real misuse (handle from `SCP` instance A used on `SCP` instance B) with a clear, actionable error.

### 5. `shutdown(timeout: Duration)` replaces terminal infallible shutdown

`BridgeInstance::shutdown` gains a `timeout: Duration` argument and becomes async. Internally it uses a `tokio_util::sync::CancellationToken` propagated into every long-running task, a `JoinSet` of spawned workers, and a bounded wait. Outstanding work gets the full timeout to drain; anything still running at the deadline is forcibly cancelled via the token.

Signature across bridges:

- PyO3: `scp.shutdown(timeout_ms: int)` — async via the bridge's tokio runtime
- NAPI: `await scp.shutdown(timeoutMs)` — async NAPI function
- UniFFI: `suspend fun shutdown(timeoutMs: Long)` (Kotlin) / `func shutdown(timeoutMs: UInt64) async` (Swift)

This is a breaking change versus the Phase 4a `shutdown()` that took no arguments. Migration is mechanical: pass a sensible default (e.g. 30 seconds). Documented in the Phase 4 migration guide (PR 4).

## Consequences

- **Tests parallel-safe on every bridge.** Per-test `SCP` fixtures eliminate `BRIDGE_LIFECYCLE_SERIAL`, per-test `beforeAll` in NAPI, and the module-scope poisoning on every SDK. pytest-xdist, Gradle parallel tests, and XCTest concurrency all work.
- **Multi-identity and multi-relay coexistence work.** A single process may hold multiple `SCP` instances, each with its own identity and its own relay connection. No shared mutable state leaks across them.
- **Handle misuse is caught at the boundary.** Cross-instance handle reuse returns `SCP-PERM-3030` immediately, rather than corrupting silently.
- **Shutdown is bounded and recoverable.** `shutdown(timeout)` drains outstanding work deterministically. Callers no longer deadlock on stuck tasks.
- **Deprecation warnings during sunset window.** Every call to a free-function façade emits a one-time warning. External consumers may need to configure their test runners (`pytest -W default::DeprecationWarning`, Jest custom reporter) to avoid spurious failures — covered in the migration guide.
- **Breaking change to `shutdown` signature.** Documented in the migration guide with a minimal upgrade example.

## Rejected alternatives

- **Thread-local bridge registry.** Doesn't scale across async runtimes. `tokio::spawn` moves work off the originating thread; thread-local state is invisible to the spawned task. Would require every async boundary to manually re-plumb state.
- **Per-call `context: &Scp` parameter on every function.** Too invasive. Every FFI function would grow a first parameter. The SDK surface becomes unergonomic for the common single-instance case that accounts for the vast majority of usage.
- **Serialization mutex around the global.** Fixes nothing. Multi-identity coexistence is still impossible; throughput is pessimized even in the single-instance case.
- **Naming the SDK class after FFI internals (`Bridge`, `BridgeInstance`).** The user-facing class should carry the protocol name (`SCP`), not the internal plumbing vocabulary. Matches the SDK convention set by peers (`OpenAI`, `Anthropic`, `Stripe`). `BridgeInstance` remains the internal Rust type — it is the FFI bridge's instance, and that vocabulary is correct for contributors.
- **`Box<dyn Any>` with per-bridge `clear_fn` callbacks (the Phase 4a pattern).** Replaced by per-bridge concrete structs behind a shared `BridgeInstanceCore` trait. Compile-time type safety over runtime downcasts, per the CLAUDE.md rule "enforce mechanically."

## Notes

### Shutdown-timeout integer width across FFI bridges

At the FFI boundary the `shutdown(timeout)` argument is carried as
milliseconds in an unsigned integer. The three non-WASM bridges disagree on
width:

- **NAPI**: `u32` (max ≈ 4 294 967 295 ms ≈ 49.7 days).
- **UniFFI**: `u64` (max ≈ 5 × 10¹¹ years — effectively unbounded).
- **PyO3**: `u64` via Python `int`.

The user-facing API is uniform — seconds at the SDK layer in every language
(`TimeInterval` in Swift, `Duration` in Kotlin, `float` in Python, `number`
in TypeScript). Each SDK wrapper clamps to its bridge's maximum before
crossing FFI and treats out-of-range or non-finite inputs as "wait forever
within the bridge's representable range". Swift's clamp uses `>= Double(UInt64.max) / 1000.0`
(not `>`) because `Double(UInt64.max) == 2⁶⁴` after IEEE-754 rounding — a
strict `>` would let the exact-boundary value trap in the subsequent cast
(round 3 bug-catcher finding).

Rationale for the NAPI/UniFFI asymmetry: JavaScript's `Number` safely
represents integers up to 2⁵³−1, so a `u64` at the NAPI boundary would
force callers onto `BigInt` — a real ergonomic tax for a shutdown timeout
that in practice never exceeds a few seconds. `u32` covers any realistic
value (49 days is far beyond any sensible deployment timeout) without the
`BigInt` friction. Swift/Kotlin have native 64-bit integer ergonomics, so
UniFFI exposes `u64` there without penalty. PyO3's `u64` matches UniFFI
because Python's `int` is unbounded anyway — no ergonomic cost.

This asymmetry is intentional and documented; it does NOT affect
semantics. Any SDK caller passing a value larger than its bridge's maximum
gets deterministic clamping at the boundary, not silent truncation.

### ADR numbering disambiguation (ADR-043)

Two existing ADR-043 entries coexist in-tree:

- `.docs/adrs/phase-3.md` § "Scope Registration as Handle Convention"
- `.docs/adrs/phase-6.md` § "Protocol Constants Reclassification"

When this ADR or the plan references ADR-043, the intended sense is the **phase-3** one (Scope Registration as Handle Convention). The later duplicate will be renumbered in a separate chronicler follow-up — tracked out of band, not blocking this ADR.

### Related PR sequence

Phase 4 remainder is four sequential PRs:

1. **PR 1 — Foundation.** This ADR, the `SCP` class scaffold in all three bridges, `BridgeInstanceCore` trait + per-bridge concrete struct refactor, rename `BRIDGE_INSTANCE` → `DEFAULT_BRIDGE_INSTANCE`, deprecation scaffold on the free-function façade, `instance_id`-backed handle affinity, `shutdown(timeout)` signature change and plumbing. No singletons migrated yet — free functions still forward to the default instance.
2. **PR 2 — Migrations + deletions + #1646.** Move every remaining per-identity singleton into typed fields on its per-bridge struct. Delete `EMPTY_IDENTITY_REGISTRY`, `EMPTY_UCAN_REGISTRY`, `BRIDGE_LIFECYCLE_SERIAL`. Fix `flush_all_contexts_sync` (AC3 bugs). Exhaustive security-reviewer audit of every path reaching ContextManager state.
3. **PR 3 — Persistence + multi-relay + real UniFFI crypto.** Expose `SqliteStorage` via `SCP::with_storage`. Thread persistence provider through UniFFI `ContextManager::new()` (#1260). Make `resume()` async; restore contexts + reconnect transport using stored `pending_relay_url` (#1678). Wire real `MlsCryptoProvider` through UniFFI (#1342). Integration tests for multi-relay + suspend-kill-resume-restore.
4. **PR 4 — Tests + docs + enforcement.** Per-test `SCP` fixture codemod across all four SDKs. Spec clarifications for §3.7, §22.3.1, §22.3.5 (clarifications, not semantic changes — the spec just becomes explicit about "per-identity/per-context within an `SCP` instance"). CI gates (`check-no-bridge-globals.sh`, `check-once-lock-ratchet.sh`, `check-no-default-in-tests.sh`, `check-handle-affinity.sh`). SDK capability matrix updates. Migration guide for external SDK consumers.

PR 2 and PR 3 touch independent axes and may run concurrently after PR 1. PR 4 depends on all prior.

### Spec clarifications to land in PR 4 (not this ADR)

- **§3.7 petnames.** Clarify that the per-identity petname cache is per-`SCP` instance. Two `SCP` instances holding the same identity converge via the identity-level sync protocol, not via a process-global cache. The spec does not mandate the cache; the current process-global is an implementation detail, not protocol.
- **§22.3.1 handle registries.** Clarify that handle registries are per-context within a given `SCP` instance — same as the existing semantics, just stated explicitly.
- **§22.3.5 scope registries** (ADR-043, phase-3 sense). Same clarification: per-context within an `SCP` instance.

None of these are breaking changes. They are disambiguations that were globally ambiguous and are now explicit.

### Updates to related ADRs (PR 1 scope)

- **ADR-021 (UniFFI Bridge).** Note that `SCP` is a first-class `uniffi::Object`; the 172 `#[uniffi::export]` functions that touch instance state become methods on `Scp`.
- **ADR-028 (Kotlin SDK).** Note that `NativeBindings` methods move onto `SCP`; `CoroutineBridge` refactors to own the `SCP` instance directly rather than wrapping sub-bridges.
