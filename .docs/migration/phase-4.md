# Phase 4 upgrade guide — SCP as first-class SDK object

**Target audience:** external SDK consumers upgrading past the #1549 Phase 4
merge (PR 1 → PR 2 → PR 3 → PR 4 façade deletion → PR 5 Kotlin-parity
method collapse).
**ADR:** [ADR-048 — SCP as First-Class Multi-Instance SDK Object](../adrs/ADR-048-scp-multi-instance.md)
**Status:** live — update for any breaking change landed after 2026-04-21.

Phase 4 converts the four language SDKs from a single process-wide default
bridge instance into first-class multi-instance objects (PR 1–3), deletes
the default-instance façade outright (PR 4), then collapses the per-domain
namespace classes (`Identity`, `Context`, `Relay`, `Node`, `McpServer`,
`McpClient`, `Transport`, `EventLog`) onto `SCP` itself (PR 5, ADR-048
§7). Per ADR-048 (re-scoped 2026-04-19), the builder-tenet "no deferral"
applies — there is no sunset window, no `DeprecationWarning` scaffold, no
`SCP.default()` accessor, and post-PR-5 there are no free-function or
namespace-static entry points: **every stateful operation is an instance
method on `SCP`**. The four SDK surfaces are now Python 162 / TypeScript
181 / Kotlin 137 / Swift per-handle methods, respectively.

---

## Table of contents

1. [Breaking changes](#breaking-changes) — what you must change to upgrade
2. [New surface](#new-surface) — what is now available
3. [Per-test `SCP` fixture — the recipe](#per-test-scp-fixture--the-recipe)
4. [CI gates](#ci-gates)

---

## Breaking changes

### 1. `SCP()` constructor is required — free-function façade deleted, namespace classes collapsed

Every SDK entry point that previously delegated to a process-wide default
instance is gone (PR 4). Post-PR-5 the per-domain namespace classes
(`Identity`, `Context`, `Relay`, `Node`, `McpServer`, `McpClient`,
`Transport`, `EventLog`) are pure handle types with no methods — every
stateful operation is a **method on `SCP`**. Callers construct an `SCP`
at process start and invoke it directly.

```python
# Before Phase 4
from scp_sdk import Identity, Context
identity = await Identity.create(custody="in_memory")
ctx = await Context.create(creator=identity, ...)

# After Phase 4 PR 5 (Kotlin-parity — ADR-048 §7)
from scp_sdk import SCP
with SCP() as scp:
    identity = await scp.identity_create("in_memory")
    ctx = await scp.context_create(identity.did, {...})
```

```typescript
// Before Phase 4
import { Identity, Context } from "@limn-works/scp-ts";
const identity = await Identity.create({ custody: "in_memory" });
const ctx = await Context.create(identity, { ceiling, memoryScope });

// After Phase 4 PR 5 (Kotlin-parity — ADR-048 §7)
import { SCP } from "@limn-works/scp-ts";
const scp = new SCP();
try {
  const identity = await scp.identityCreate("in_memory");
  const ctx = await scp.contextCreate(identity.did, {...});
} finally {
  await scp.shutdown(5);
}
```

Pure protocol helpers that touch no registry state (hashing, encoding,
shape-only validation, `defineToolDefinition`, `parseAddress`) remain as
free functions. Swift retains per-handle `#[uniffi::Object]` wrappers
alongside `Scp.swift` — UniFFI does not expose a mechanism to collapse
`#[uniffi::Object]` receivers into methods on an unrelated outer object
without hand-written shims, so Swift callers invoke methods on the
generated handle types (`ctx.send(payload)`) rather than on `scp`.
Semantically the surface is identical — every handle still carries the
issuing `SCP`'s `instance_id` and every operation crosses the same
handle-affinity gate.

### 2. `SCP.resume()` is async (#1678)

`BridgeInstanceCore::resume` is `async fn`; per-bridge overrides chain
relay reconnection and persisted-context restoration on top of the
suspended-flag flip.

- **Python** — `await scp.resume()` (PyO3 spawns the async work on the
  shared runtime via `asyncio.to_thread`).
- **TypeScript** — `await scp.resume()` (NAPI returns a `Promise<void>`).
- **Swift** — `try await scp.resume()`.
- **Kotlin** — `scp.resume()` from inside a coroutine or `suspend fun`.

Reconnect failures surface through the new
`LifecycleError.ReconnectFailed { url, reason }` variant. The first failed
URL is returned; successfully-reconnected URLs remain in the pending set
so callers may retry individually. See ADR-048 § "Async `resume()`
semantics".

### 3. `shutdown` takes a timeout and is async (#1549 PR 1)

`BridgeInstance::shutdown` accepts a `timeout: Duration` and is async
internally. Outstanding work gets the full timeout to drain; anything
still running at the deadline is forcibly cancelled via
`tokio_util::sync::CancellationToken`.

- **Python** — `scp.shutdown(5.0)` (seconds as `float`; the SDK wrapper
  converts to milliseconds and clamps to `u64::MAX`). Also runs
  automatically on `with SCP() as scp: ...` scope exit.
- **TypeScript** — `await scp.shutdown(5)` (seconds as `number`; the SDK
  wrapper converts to milliseconds and clamps to
  `Number.MAX_SAFE_INTEGER`).
- **Swift** — `try await scp.shutdown(timeoutMillis: 5_000)`.
- **Kotlin** — `scp.shutdown(timeoutMillis = 5_000uL)` from inside a
  coroutine.

All three non-WASM FFI bridges carry `shutdown(timeout)` as `u64`
milliseconds uniformly (NAPI was widened from `u32` in #1692). The SDK
wrappers clamp non-finite or out-of-range inputs to a safe cap at the
boundary — TypeScript uses `Number.MAX_SAFE_INTEGER`, Swift uses a
`Double` range check, Python/Kotlin rely on their native 64-bit integer
types. See ADR-048 § "Shutdown-timeout integer width across FFI
bridges".

### 4. `StorageConfig::Sqlite { path, key }` (#1491, #1260)

`StorageConfig` gained a `Sqlite { path: String, key: Vec<u8> }` variant
across all three non-WASM bridges. The 32-byte SQLCipher key is validated
at the FFI boundary; length mismatches return `ScpError::Validation`.

- **Python** — `SCP(storage={"type": "sqlite", "path": str, "key": bytes})`.
- **TypeScript** — `new SCP({ storage: { type: "sqlite", path, key } })`
  where `key` is a hex string OR `Uint8Array`.
- **Swift** — `SCP.withStorage(StorageConfig.sqlite(path:key:))`.
- **Kotlin** — `SCP.withStorage(StorageConfig.Sqlite(path, key))`.

### 5. UniFFI `ContextManager` requires a local DID (#1342)

`FfiBridgeCrypto` is deleted. The UniFFI bridge constructs
`MlsCryptoProvider::new(did)` exactly like PyO3 and NAPI. Every context
operation (`context_create`, `context_join`, `context_import`) requires
a DID to have been registered via `scp.registerLocalDid(…)` first.

- **Swift / Kotlin** — calling a context operation before
  `scp.registerLocalDid(...)` returns
  `ScpError.Context { code: "CTX_2000", msg: "bridge not ready: no local DID registered" }`.

```swift
// Before
let scp = SCP()
try await scp.contextCreate(params)

// After
let scp = SCP()
try scp.registerLocalDid(didString)
try await scp.contextCreate(params)
```

### 6. Multi-relay `HashSet` accessors (#1678)

`CoreFields::relay_url: Mutex<Option<String>>` is replaced with
`relay_urls: Mutex<HashSet<String>>`. The old accessors go away; the new
ones are additive.

| Before                                          | After                                           |
| ----------------------------------------------- | ----------------------------------------------- |
| `set_relay_url(url)`                            | `add_relay_url(url)`                            |
| `clear_relay_url()`                             | `remove_relay_url(url)` *(per-URL)*             |
| `pending_relay_url() -> Option<String>`         | `pending_relay_urls() -> Vec<String>`           |

Each per-bridge `resume()` override iterates the pending set and
reconnects each URL via `reconnect_transport_if_pending`. Reconnected
URLs remain in the pending set so a later resume reconnects them again.
Adapters are appended to a single `TransportManager` — the multi-relay
invariant (N adapters before suspend → N adapters after resume) holds.

### 7. `register_local_did` returns `Result<(), ScpError>` (UniFFI, #1342)

Previously infallible. Now returns `ScpError::Validation` when the DID
string fails `Did::from_str` parsing. Callers must `try`/handle the
error.

### 8. Python extension `Vec<u8>` returns are `bytes` (PyO3 0.24 upgrade)

All PyO3 FFI functions returning `Vec<u8>` produce Python `bytes` (not
`list[int]`). This is the correct binary-data shape for the 7 affected
functions; callers that previously coerced via `bytes(result)` can drop
the coercion. Pre-dates Phase 4 but listed for upgrade completeness.

---

## New surface

### `SCP()` constructor

The sole public entry point in all four non-WASM SDKs. Each call
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

`repr(scp)` / `toString()` surfaces `instance_id` so multi-instance
processes get legible log output.

### Per-instance lifecycle methods

`suspend()`, `resume()`, and `shutdown(timeoutMillis)` are instance
methods on `SCP`. The Python wrapper also exposes synchronous context
manager semantics (`with SCP() as scp: ...`) that call `shutdown(5.0)`
on exit.

---

## Per-test `SCP` fixture — the recipe

This is the canonical test pattern. Every SDK test constructs its own
`SCP` so that:

- pytest-xdist, Gradle parallel tests, and XCTest concurrency are safe;
- cross-test leakage (a test mutating a registry that the next test
  reads) is impossible by construction;
- the `BRIDGE_LIFECYCLE_SERIAL` mutex in NAPI's `lifecycle.test.ts` — and
  every equivalent — is deleted.

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
    instance.shutdown(5.0)
```

```python
# tests/test_whatever.py
async def test_context_create(scp: scp_sdk.SCP) -> None:
    identity = await scp_sdk.Identity.create(scp, custody="in_memory")
    ctx = await scp_sdk.Context.create(scp, creator=identity, ...)
    assert ctx.instance_id == scp.instance_id
```

### TypeScript (bun test)

```ts
// tests/lifecycle.test.ts
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { SCP, Identity, Context } from "@limn-works/scp-ts";

describe("lifecycle", () => {
  let scp: SCP;

  beforeEach(() => {
    scp = new SCP();
  });

  afterEach(async () => {
    await scp.shutdown(5);
  });

  test("context_create", async () => {
    const identity = await Identity.create(scp, { custody: "in_memory" });
    const ctx = await Context.create(identity, params);
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
        try await scp.shutdown(timeoutMillis: 5_000)
        scp = nil
        try await super.tearDown()
    }

    func testContextCreate() async throws {
        try scp.registerLocalDid(didString)
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
        scp.shutdown(timeoutMillis = 5_000uL)
    }

    @Test
    fun `context_create`() = runBlocking {
        scp.registerLocalDid(didString)
        val ctx = scp.contextCreate(params)
        assertEquals(scp.instanceId, ctx.instanceId)
    }
}
```

---

## CI gates

Phase 4 adds three required gates on every PR touching `bindings/**` or
`crates/scp-ffi/**`:

| Gate script                              | Guards                                                                           | Failure remediation                                                               |
| ---------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `scripts/check-no-bridge-globals.sh`     | New `static OnceLock` at module scope in FFI bridges (ratcheted, never grows up) | Move state onto the per-bridge instance, or extend the allowlist with rationale.  |
| `scripts/check-no-fallback-registry.sh`  | Reintroduction of `EMPTY_IDENTITY_REGISTRY` / `EMPTY_UCAN_REGISTRY` in code      | Make the accessor return `Result<&T, ScpError>`; don't silently fall back.        |
| `scripts/check-handle-affinity.sh`       | Handle-accepting FFI function without its bridge's affinity macro                 | Add the macro invocation in the function prologue.                                |

All three gates are listed in the `NEVER modify enforcement files to
bypass failures` block in repo-root `CLAUDE.md`. Adding NEW assertions is
always welcome; weakening or exempting existing ones requires human
approval.

---

## Related artifacts

- [ADR-048 — SCP as First-Class Multi-Instance SDK Object](../adrs/ADR-048-scp-multi-instance.md)
- [ADR-021 — UniFFI Bridge](../adrs/phase-2.md) — Phase 4 notes that
  `SCP` is a first-class `uniffi::Object`.
- [ADR-028 — Kotlin SDK](../adrs/phase-3.md) — Phase 4 notes that
  `NativeBindings` methods move onto `SCP`.
- [SDK capability matrix](../standards/sdk-capability-matrix.json) — the
  `Lifecycle` domain lists every `SCP::method` added by Phase 4.
- [CHANGELOG](../../CHANGELOG.md) — per-release breaking-change summary.
