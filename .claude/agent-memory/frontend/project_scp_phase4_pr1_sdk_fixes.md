---
name: SCP Phase 4 PR 1 SDK review fixes (#1549, ADR-048)
description: Second pass on SDK wrappers after coder H's Rust ms unification — shutdown units, deprecation scaffold completion, Kotlin AutoCloseable removal, TS StorageConfig tightening
type: project
---

Follow-up commit after `0040d67d9` and coder H's Rust-side ms unification (`183311e97`). Addresses SDK-side api-design / architecture / test-quality / simplifier review findings on #1549 Phase 4 PR 1.

**Why:** The shared-runtime Rust shutdown API in `183311e97` now takes `timeout_millis` across all 3 bridges (PyO3/NAPI/UniFFI) where it used to be a mix of f64 seconds / u32 seconds. SDK wrappers now convert their ergonomic public types (Python float, TS number seconds, Swift TimeInterval, Kotlin Duration) to u64/u32 milliseconds before crossing FFI.

**How to apply:** When adding new SDK-level lifecycle methods, follow the same pattern — public API uses the natural time type for the SDK language, conversion happens at the SDK boundary, never at call sites. For persistence parameter: do NOT re-expose until PR 3 — track #1260 and #1491.

**Notable state:**
- NAPI `context_subscribe` is now `async` (returns `Promise<void>`). TS SDK callers must `await` it. Bridge interface, native.ts, wasm.ts adapter, mock-bridge, and several tests updated.
- Python `SCP.default()` now emits a module-level one-time DeprecationWarning (tracked via `_default_deprecation_emitted` sentinel). `test_deprecation.py::test_scp_class_default_emits_deprecation_on_first_call` was previously an anti-assertion — inverted.
- Swift free-function deprecation annotations inserted by `python3.12` script (grepped for `Bridge.default[A-Z]` as the default-bridge marker) across Discovery/Mcp/Media/Provenance/Sync/Trust/Ucan.
- TS `StorageConfig` tightened to closed union `{ type: "in_memory" }` — the open `{ type: string; ... }` branch swallowed typos; PR 3 extends to `{ type: "sqlite"; path: string; key: string }`.
- TS WASM unavailability + NAPI load failures now raise `ValidationError` with `SCP-VALID-7005` (was `TransportError` / `SCP-TRANS-5001` — mis-categorized as a transport fault).
- TS deprecation gate: `scripts/check-ts-deprecation-calls.py` + shell wrapper. Skip list for pure helpers; checks every `export function`/`export async function` in default-bridge-routing files.
- Kotlin `SCP` no longer implements `AutoCloseable` — the silent `close()` no-op was a footgun.
- Kotlin `ScpClassTest.kt` deleted — every test was `@Disabled` with an `error()` stub bridge. Misleading coverage worse than no coverage.
- Rust `shutdown_core_async_times_out_with_long_task` budget raised to 500 ms (was flaky at 100 ms) — `tokio::time::pause()` doesn't help because `drain_under_deadline` uses `std::time::Instant::now()`.
- TS lifecycle.test.ts has 2 pre-existing failures because `@limn-works/scp-ts-napi-darwin-arm64` isn't published — not caused by this commit.
