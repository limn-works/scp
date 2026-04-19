# Phase 4 migration guide — SCP as first-class SDK object

**Target audience:** external SDK consumers upgrading past the #1549 Phase 4
merge (PR 1 → PR 2 → PR 3 → PR 4).
**ADR:** [ADR-048 — SCP as First-Class Multi-Instance SDK Object](../adrs/ADR-048-scp-multi-instance.md)
**Status:** live — update for any breaking change landed after 2026-04-18.

Phase 4 converts the four language SDKs from a single process-wide default
bridge instance into first-class multi-instance objects. Most of the change
is additive, but a handful of signatures move — the list below enumerates
every known breaking change, every new convenience, and the mechanical
codemod that migrates a test suite from the free-function façade onto a
per-test `SCP` fixture.

---

## Table of contents

1. [Breaking changes](#breaking-changes) — what is mandatory to update
2. [New surface](#new-surface) — what is now available
3. [Deprecations](#deprecations) — what still works but is marked for removal
4. [Per-test `SCP` fixture — the recipe](#per-test-scp-fixture--the-recipe)
5. [Opt-in tag: `SCP-DEFAULT-INSTANCE-OK`](#opt-in-tag-scp-default-instance-ok)
6. [CI gates](#ci-gates)

---

## Breaking changes

### 1. `SCP.resume()` is now async (#1678)

`BridgeInstanceCore::resume` became `async fn` so per-bridge overrides can
chain relay reconnection and persisted-context restoration on top of the
suspended-flag flip.

- **Python** — `await scp.resume()` (was synchronous `scp.resume()`).
- **TypeScript** — `await scp.resume()` (returns `Promise<void>`; the NAPI
  binding previously returned `void` synchronously).
- **Swift** — `try await scp.resume()` (was synchronous `throws`).
- **Kotlin** — `scp.resume()` from inside a coroutine or `suspend fun` (was
  a blocking `ffiCall`).

Reconnect failures surface through the new `LifecycleError.ReconnectFailed
{ url, reason }` variant. The first failed URL is returned; successfully-
reconnected URLs remain in the pending set so callers may retry
individually. See ADR-048 § "Async `resume()` semantics".

Codemod sketch (Python):

```python
# Before (Phase 4 PR 1)
scp.suspend()
# ... mobile backgrounding ...
scp.resume()

# After (Phase 4 PR 3+)
await scp.suspend()  # async since PR 3
try:
    await scp.resume()
except LifecycleError as e:
    # e.code == "LC_0003" — reconnect failure
    log.warning("resume could not reconnect %s: %s", e.url, e.reason)
    # The SCP is resumed; the pending set still holds e.url. Retry by
    # calling scp.add_relay_url(e.url) followed by another resume.
```

### 2. `shutdown` takes a `timeout` argument and is async (#1549 PR 1)

`BridgeInstance::shutdown` now accepts a `timeout: Duration` and is async
internally. Outstanding work gets the full timeout to drain; anything still
running at the deadline is forcibly cancelled via
`tokio_util::sync::CancellationToken`.

- **Python** — `await scp.shutdown(5.0)` (seconds as `float`; the SDK
  wrapper converts to milliseconds and clamps to `u64::MAX`).
- **TypeScript** — `await scp.shutdown(5)` (seconds as `number`; the SDK
  wrapper converts to milliseconds and clamps to `u32::MAX`).
- **Swift** — `try await scp.shutdown(timeout: .seconds(5))` or
  `try await scp.shutdown(timeout: 5.0)` (TimeInterval).
- **Kotlin** — `scp.shutdown(5.seconds)` from inside a coroutine.

The timeout-integer widths differ across bridges intentionally — NAPI uses
`u32` (49-day ceiling, avoids BigInt), UniFFI and PyO3 use `u64`. The SDK
wrappers clamp to each bridge's representable range, treating out-of-range
or non-finite inputs as "wait forever within the bridge's range". See
ADR-048 § "Shutdown-timeout integer width across FFI bridges".

### 3. `StorageConfig::Sqlite { path, key }` (#1491, #1260)

`StorageConfig` gained a `Sqlite { path: String, key: Vec<u8> }` variant
across all three non-WASM bridges. The 32-byte SQLCipher key is validated
at the FFI boundary; length mismatches return `ScpError::Validation`.

- **Python** — `SCP(storage={"type": "sqlite", "path": str, "key": bytes})`.
- **TypeScript** — `SCP.withStorage({ type: "sqlite", path, key })` where
  `key` is a hex string OR `Uint8Array`.
- **Swift** — `SCP.withStorage(sqliteDir: URL, key: Data)` convenience, or
  `StorageConfig.sqlite(path:key:)` directly.
- **Kotlin** — `SCP.withSqlite(dir: File, key: ByteArray)` companion, or
  `StorageConfig.Sqlite(path, key)` directly.

### 4. UniFFI `ContextManager` requires a local DID (#1342)

`FfiBridgeCrypto` is deleted. The UniFFI bridge now constructs
`MlsCryptoProvider::new(did)` exactly like PyO3 and NAPI. Every context
operation (`context_create`, `context_join`, `context_import`) requires a
DID to have been registered via `register_local_did(…)` first.

- **Swift / Kotlin** — calling a context operation before
  `scp.registerLocalDid(...)` returns
  `ScpError.Context { code: "CTX_2000", msg: "bridge not ready: no local DID registered" }`.

Workflow change:

```swift
// Before (PR 2)
let scp = SCP()
try await scp.contextCreate(params)

// After (PR 3+)
let scp = SCP()
try scp.registerLocalDid(didString)
try await scp.contextCreate(params)
```

### 5. Multi-relay `HashSet` accessors (#1678)

`CoreFields::relay_url: Mutex<Option<String>>` is replaced with
`relay_urls: Mutex<HashSet<String>>`. The old accessors go away; the new
ones are additive.

| Before                                          | After                                           |
| ----------------------------------------------- | ----------------------------------------------- |
| `set_relay_url(url)`                            | `add_relay_url(url)`                            |
| `clear_relay_url()`                             | `remove_relay_url(url)` *(per-URL)*             |
| `pending_relay_url() -> Option<String>`         | `pending_relay_urls() -> Vec<String>`           |

Each per-bridge `resume()` override iterates the pending set and reconnects
each URL via `reconnect_transport_if_pending`. Reconnected URLs remain in
the pending set so a later resume reconnects them again. Adapters are
appended to a single `TransportManager` — the multi-relay invariant
(N adapters before suspend → N adapters after resume) holds.

### 6. `register_local_did` returns `Result<(), ScpError>` (UniFFI, #1342)

Previously infallible. Now returns `ScpError::Validation` when the DID
string fails `Did::from_str` parsing. Callers must `try`/handle the error.

### 7. Python extension `Vec<u8>` returns are `bytes` (PyO3 0.24 upgrade,
unchanged from pre-Phase-4 but worth restating for migration docs)

All PyO3 FFI functions returning `Vec<u8>` produce Python `bytes` (not
`list[int]`). This is the correct binary-data shape for the 7 affected
functions; callers that previously coerced via `bytes(result)` can drop
the coercion.

---

## New surface

### `SCP()` constructor

The non-deprecated entry point in all four non-WASM SDKs. Each call
allocates a fresh per-bridge instance (`PyBridgeInstance` /
`NapiBridgeInstance` / `UniffiBridgeInstance`) with its own registries,
ContextManager, transport manager, and monotonic `instance_id`.

```python
from scp_sdk import SCP

scp = SCP()                                    # default (in-memory)
scp = SCP(storage={"type": "in_memory"})       # explicit
scp = SCP(storage={"type": "sqlite",
                    "path": "/var/scp.db",
                    "key": sqlcipher_key_32b})
```

### `instance_id: u64`

Read-only monotonic identifier assigned at construction. Every handle
type (`ContextHandle`, `Identity`, `UcanToken`, `MessageReceiver`,
`TransportManager`, `RelayHandle`, `NodeHandle`, `DIDDocument`) carries
the `instance_id` of its owning `SCP`. Every handle-accepting FFI
function runs a cheap runtime check and returns `SCP-PERM-3030` on
mismatch. The check is enforced mechanically by
`scripts/check-handle-affinity.sh`.

```swift
let a = SCP()
let b = SCP()
let ctx = try await a.contextCreate(params)
// ctx.instanceId == a.instanceId

try await b.contextSend(ctx, payload)
// throws ScpError.Permission(code: "SCP-PERM-3030")
```

### `scp.instance_id` as debugging affordance

`repr(scp)` / `toString()` surfaces `instance_id` so multi-instance
processes get legible log output.

---

## Deprecations

### Free-function façade on the default instance

Every free-function SDK entry point that implicitly operated on the
process-wide default bridge instance is now decorated with a one-time
DeprecationWarning scaffold:

- **Python** — `@deprecated_default_instance` in `scp_sdk._deprecation`;
  emits `warnings.warn(..., DeprecationWarning)` on first call per
  interpreter session.
- **TypeScript** — each free-function export calls `console.warn(...)`
  exactly once per process (tracked via a module-level Set).
- **Swift** — annotated with
  `@available(*, deprecated, message: "Use SCP().contextCreate(…) instead")`.
- **Kotlin** — annotated with
  `@Deprecated("Use SCP().contextCreate(…) instead")`.

**Removal target:** two release cycles after Phase 4 merge.

External test suites running with strict warning policies
(`pytest -W error::DeprecationWarning`, Jest custom reporters that fail on
`console.warn`) may see spurious failures. Migrate the test to the per-test
`SCP` fixture — or, for tests that deliberately exercise the façade to
verify deprecation behavior, filter the specific warning. Example pytest
config:

```toml
# pyproject.toml
[tool.pytest.ini_options]
filterwarnings = [
    "default::DeprecationWarning:scp_sdk.*",
]
```

### `SCP.default()` accessor

`SCP.default()` is also deprecated. It is the last remaining explicit path
onto the process-wide `DEFAULT_BRIDGE_INSTANCE`. Same one-time warning
behavior as the free-function façade. Same removal target.

---

## Per-test `SCP` fixture — the recipe

This is the canonical codemod. Every SDK test that previously relied on the
process-wide default instance must move to a per-test fixture so that:

- pytest-xdist, Gradle parallel tests, and XCTest concurrency are safe;
- cross-test leakage (a test mutating a registry that the next test reads)
  is impossible by construction;
- the `BRIDGE_LIFECYCLE_SERIAL` mutex in NAPI's `lifecycle.test.ts` — and
  every equivalent — is no longer needed.

### Python (pytest)

```python
# tests/conftest.py
import pytest
import scp_sdk


@pytest.fixture
def scp() -> scp_sdk.SCP:
    """Per-test SCP instance. Function-scope ⇒ fresh per test."""
    instance = scp_sdk.SCP()
    yield instance
    # Bounded teardown — shutdown returns a coroutine now.
    import asyncio
    asyncio.get_event_loop().run_until_complete(instance.shutdown(5.0))
```

```python
# tests/test_whatever.py
async def test_context_create(scp: scp_sdk.SCP) -> None:
    ctx = await scp.context_create(params)
    assert ctx.instance_id == scp.instance_id
```

### TypeScript (bun test)

```ts
// tests/lifecycle.test.ts
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { SCP } from "@limn-works/scp-ts";

describe("lifecycle", () => {
  let scp: SCP;

  beforeEach(() => {
    scp = new SCP();
  });

  afterEach(async () => {
    await scp.shutdown(5);
  });

  test("context_create", async () => {
    const ctx = await scp.contextCreate(params);
    expect(ctx.instanceId).toBe(scp.instanceId);
  });
});
```

### Swift (XCTest)

```swift
import XCTest
@testable import SCP

final class LifecycleTests: XCTestCase {
    var scp: SCP!

    override func setUp() async throws {
        try await super.setUp()
        scp = SCP()
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeout: 5)
        scp = nil
        try await super.tearDown()
    }

    func testContextCreate() async throws {
        let ctx = try await scp.contextCreate(params)
        XCTAssertEqual(ctx.instanceId, scp.instanceId)
    }
}
```

### Kotlin (JUnit 5)

```kotlin
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import works.limn.scp.SCP

class LifecycleTests {
    private lateinit var scp: SCP

    @BeforeEach
    fun setUp() {
        scp = SCP()
    }

    @AfterEach
    fun tearDown() = runBlocking {
        scp.shutdown(5.seconds)
    }

    @Test
    fun `context_create`() = runBlocking {
        val ctx = scp.contextCreate(params)
        assertEquals(scp.instanceId, ctx.instanceId)
    }
}
```

---

## Opt-in tag: `SCP-DEFAULT-INSTANCE-OK`

`scripts/check-no-default-in-tests.sh` fails the build if a test file calls
a known free-function façade (`scp_sdk.context_create(...)`,
`.contextCreate(...)`, etc.) without an explicit opt-in tag on the same
line or within 2 lines above.

The tag forces a deliberate, reviewable choice. The default action is to
migrate the test to the per-test fixture above; the tag exists for
legitimate cases:

- tests that verify the deprecation warning fires on the façade;
- tests that validate cross-instance isolation by constructing handles
  against both the default and an explicit `SCP()`.

Tag format (on the offending line or within 2 lines above):

```python
# SCP-DEFAULT-INSTANCE-OK: verifies DeprecationWarning on free-function façade
scp_sdk.context_create(params)
```

```ts
// SCP-DEFAULT-INSTANCE-OK: validates cross-instance isolation error code
scpSdk.contextCreate(params);
```

Supply a reason that names the specific behavior being exercised. Reviewers
will reject tags like `SCP-DEFAULT-INSTANCE-OK: legacy` that do not
identify a concrete test contract.

---

## CI gates

Phase 4 adds four gates that run on every PR touching `bindings/**` or
`crates/scp-ffi/**`:

| Gate script                              | CI status            | Guards                                                                           | Failure remediation                                                               |
| ---------------------------------------- | -------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `scripts/check-no-bridge-globals.sh`     | **required**         | New `static OnceLock` at module scope in FFI bridges (ratcheted, never grows up) | Move state onto the per-bridge instance, or extend the allowlist with rationale. |
| `scripts/check-no-fallback-registry.sh`  | **required**         | Reintroduction of `EMPTY_IDENTITY_REGISTRY` / `EMPTY_UCAN_REGISTRY` in code      | Make the accessor return `Result<&T, ScpError>`; don't silently fall back.        |
| `scripts/check-no-default-in-tests.sh`   | **staged, not yet required** | Free-function façade calls in test files without the `SCP-DEFAULT-INSTANCE-OK` tag | Rewrite the test to the per-test `SCP` fixture, or add the tag with a reason.     |
| `scripts/check-handle-affinity.sh`       | **required**         | Handle-accepting FFI function without its bridge's affinity macro                 | Add the macro invocation in the function prologue.                                |

The `check-no-default-in-tests.sh` gate is staged for a follow-up PR that
completes the per-test `SCP` fixture codemod across all four SDKs. Running
the gate today reports on the order of 500 pre-existing call sites that
must migrate first. The script is ready; the wiring lights up once the
codemod lands.

All four gates are listed in the `NEVER modify enforcement files to bypass
failures` block in repo-root `CLAUDE.md`. Adding NEW assertions is always
welcome; weakening or exempting existing ones requires human approval.

---

## Related artifacts

- [ADR-048 — SCP as First-Class Multi-Instance SDK Object](../adrs/ADR-048-scp-multi-instance.md)
- [ADR-021 — UniFFI Bridge](../adrs/phase-2.md) — Phase 4 notes that `SCP`
  is a first-class `uniffi::Object`.
- [ADR-028 — Kotlin SDK](../adrs/phase-3.md) — Phase 4 notes that
  `NativeBindings` methods move onto `SCP`.
- [SDK capability matrix](../standards/sdk-capability-matrix.json) — the
  `Lifecycle` domain lists every `SCP::method` added by Phase 4.
- [CHANGELOG](../../CHANGELOG.md) — per-release breaking-change summary.
