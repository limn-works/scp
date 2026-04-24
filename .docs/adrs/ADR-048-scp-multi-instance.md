# ADR-048: SCP as First-Class Multi-Instance SDK Object

**Status:** Accepted
**Date:** 2026-04-18 (re-scoped 2026-04-19 — façade deleted in PR 4, no deprecation window)
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

**Approved exemption — shared-variant types for storage-backed repositories.** The rule "per-bridge concrete structs, no shared type-erased slots" has one deliberate carve-out: types that enumerate a **closed, protocol-level** set of storage backends. `ProtocolRepoVariant { InMemory(…), Sqlite(…) }` is the canonical case. It is not bridge plumbing — the variants are dictated by `StorageConfig` (itself protocol-shaped: in-memory vs. persistent SQLCipher), the `Storage` trait is `scp_platform`-level, and every non-WASM bridge dispatches identically over the same arms. Duplicating the enum into `NapiProtocolRepoVariant` + `UniffiProtocolRepoVariant` + `PyProtocolRepoVariant` produces three identical match statements with no extra type safety — each bridge already owns its own concrete instance type, so the enum lives on a per-bridge field without ambiguity. The exemption is **narrow**: it applies only to closed-set enums whose variants trace to a protocol-level configuration type (today: `StorageConfig`). It does not re-admit `Box<dyn Any>`, runtime downcasts, or open-ended trait objects — those remain rejected per Phase 4a. `ProtocolRepoVariant` has been promoted into `scp-ffi-common` so the three bridges share the single definition; the carve-out is documented here so future maintainers do not re-litigate the decision.

### 3. Default-instance façade is DELETED in PR 4 (no deprecation window)

**Re-scoped 2026-04-19 per builder tenet "no deferral" and pre-release posture (no external consumers).** The earlier draft of this ADR called for `DEFAULT_BRIDGE_INSTANCE` and every free-function façade to remain in place for a two-release-cycle sunset window. That plan is abandoned.

The façade is **removed in PR 4 alongside the `SCP` migration**:

- `DEFAULT_BRIDGE_INSTANCE: OnceLock<Arc<{Py,Napi,Uniffi}BridgeInstance>>` — deleted in all three bridges.
- Every free-function export that forwarded to the default instance — deleted (`py_context_create`, `napi context_create`, UniFFI `context_create`, and every sibling on all three bridges).
- `SCP.default()` factories on all four SDKs — deleted.
- Deprecation scaffolding (`_deprecation.py`, `internal/deprecation.ts`, `@available(*, deprecated)`, `@Deprecated` annotations) — deleted. No `DeprecationWarning` is emitted because there is no façade left to deprecate.
- `scripts/check-no-default-in-tests.sh` and every `SCP-DEFAULT-INSTANCE-OK: <reason>` opt-in tag — deleted. The gate exists to police use of a façade that no longer exists; the tags are attached to tests that no longer call deleted functions. Both are removed together.

**Rationale for the re-scope.** SCP is pre-release. There are no external callers of the free-function façade — every consumer lives in this repository. A deprecation window buys nothing a redundant migration cannot buy better: it adds a second round of churn (first to deprecated, then to deleted), keeps the test-serialization scaffolding live for the duration, and defers enforcement gates that the codebase was designed around. The builder tenet "no deferral" applies — the work is done now, in one PR, not split across two release cycles.

Every call site that previously used the façade routes through a fresh `SCP()` instance per test, or through an application-owned `SCP` instance in long-lived code. Phases A-D of PR 4 migrated all four SDKs and all ~200 test files mechanically. Phase E (this phase) deletes the enforcement gate and opt-in tags that the migration made obsolete.

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

### 6. Long-lived background tasks capture `Weak<BridgeInstance>`, not `Arc`

Every long-lived task spawned on the shared tokio runtime that needs access to the per-instance state captures a `std::sync::Weak<BridgeInstance>`, not a strong `Arc`. Inside the task, the reference is upgraded per event; a `None` upgrade signals that the caller dropped the `SCP` and the task exits cleanly. Each task body also selects on `bridge_instance.core.cancel_token().cancelled()` so `emergency_cancel_tasks` (invoked by `impl Drop for BridgeInstance`) terminates them promptly.

Rationale: without this, a `tokio::spawn(async move { ... bi: Arc<BridgeInstance> ... })` keeps the bridge alive as long as the task is scheduled, even after the caller drops the owning `SCP`. The cycle would leak `ContextManager`, identity custody, relay connections, and MLS group state for the life of the process.

Covered spawn sites (all three bridges):

- `spawn_suppression_scoring_task` — transport suppression scoring (PyO3, UniFFI; NAPI already used `Weak` pre-PR).
- `FfiBridgeProvider.bi` / `McpUniFfiBridgeProvider.bi` — MCP server providers — `Weak<BridgeInstance>` field; every `ContextProvider` trait method `upgrade()`s and returns safe defaults when the upgrade fails.
- `py_mcp_serve` / `mcp_server_create` — stdio/SSE server loops capture `sse_bi: Weak<BridgeInstance>`, select on `cancel_token.cancelled()` alongside `read_line().await`.

Short-lived tasks (single-await-then-return) are allowed to hold an `Arc` for the duration of their work; they cannot delay Drop by more than one event. Tool-invocation paths are bounded by `FFI_TOOL_TIMEOUT_MS` (30 s) at the sync `recv_timeout` barrier, so a misbehaving tool handler delays Drop by at most one invocation's timeout.

Regression tests at `crates/scp-ffi/src/transport.rs::tests`, `crates/scp-ffi/src/mcp.rs::tests`, and `crates/scp-ffi/uniffi/src/bridge.rs::tests` assert (a) `Arc::strong_count(&bi) == 1` while the task is parked, and (b) `weak.upgrade().is_none()` once the caller-held `Arc` drops — proving `impl Drop for BridgeInstance` runs and `emergency_cancel_tasks` propagates.

### 7. SDK-level Kotlin-parity: SCP methods are the sole entry point

Every SDK wraps the NAPI `Scp` surface (and its PyO3/UniFFI siblings) as instance methods on its own `SCP` class. The pre-Phase-4 shape — a three-method `SCP` lifecycle object alongside a parallel collection of namespace classes (`Identity`, `Context`, `Transport`, `EventLog`, `McpServer`, `McpClient`, `Relay`, `Node`) with their own lifecycle methods plus ~140 free functions — is gone. There is one class, one surface, one entry point:

- **Python:** `scp_sdk.SCP` carries 162 methods (was 3).
- **TypeScript:** the `SCP` class in `bindings/typescript/src/scp.ts` carries 181 methods (was 3).
- **Kotlin:** `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Scp.kt` carries 137 methods. Kotlin was the reference shape — it already expressed this surface via `CoroutineBridge` before Phase 4. Python and TypeScript now match.

The namespace classes collapsed to pure handle types — `Identity { did, custodyType }`, `Context { contextId, identityDid }`, `Transport { handle }`, `EventLog { handle }`, `McpServer { handle }`, `McpClient { handle }`, `Relay { handle, relayPort }`, `Node { handle, relayPort }` — with no methods. Every lifecycle, content, governance, economy, attestation, sync, discovery, event-log, MCP, relay, and node operation is a method on `SCP` (`scp.contextCreate(...)`, `scp.ucanMint(...)`, `scp.eventLogQuery(handle, filter)`, `scp.relayStart(config)`, etc.). Handles are owned by the `SCP` that issued them and enforced by `instance_id` per §4.

Swift retains per-object UniFFI-generated wrappers alongside `Scp.swift` — UniFFI does not expose a mechanism to collapse `#[uniffi::Object]` receivers into methods on an unrelated outer object without hand-written shims on both sides of the bridge. Per ADR-021, UniFFI's generator constraints govern the Swift surface. Swift callers get the same semantic surface (one `SCP` instance, handle-scoped operations) with the generator's natural shape; Python, Kotlin, and TypeScript converge on the single-class form.

Commits (all on `refactor/phase4-facade-delete`, issue #1549): `dc7face6d` (Python Agent A — class scaffold), `4fb4572f8` (TS Agent A — class scaffold), `bdd2cb58a` (TS B1 — namespace class collapse), `4612e7eff` (TS B2 — Proxy mock-bridge rewrite), `ecc668bd3` (Python B+C — handle collapse + test rewrite), `cd85f3f8b` (TS B4 — large test rewrites), `5271ef84d` (TS B5 — WASM + examples).

**Round-2 and round-3 hardening (post-§7 review loop, 2026-04-21).** After the §7 migration landed the full review roster surfaced three classes of finding that were addressed in `3de6cbe30`, `78102c871`, `d8ffcdadf`, and `d489f6610`. The decisions baked into those commits supersede naïve readings of the earlier §7 framing:

- **Test-hook realm hardening (red-hat RED-PR5-001/007, black-hat BLACK-PR5-003).** The initial B-track landed `[NATIVE_HANDLE]` / `[NATIVE_SET]` Symbol-keyed accessors on the `SCP` prototype so `createMockNativeScp` could swap the native handle post-construction. `Object.getOwnPropertySymbols(SCP.prototype)` surfaced both — any in-realm import could overwrite the native handle. Round-2 replaced the Symbol accessors with two **module-local WeakMaps** (`nativeHandles` for the real handle, `nativeTestOverrides` for test-only swaps); neither is exported. The only reach-in helpers (`__getNativeScp`, `__constructScpWithNativeForTests`) hold WeakMap references by closure. Round-3 additionally gates `__constructScpWithNativeForTests` behind a runtime `NODE_ENV === "production"` guard so a deep import of `dist/scp.js` from a compromised transitive dep cannot swap the native bridge in a production deployment. `__setNativeForTests` and its companion `replaceNativeWithMock` were deleted outright — the post-construction swap was invisible to the ~180 SCP class methods that dispatch through the private `#native` field, so any test using it would have seen half-mocked state. The sole supported mock path is `mountMockScp` (constructs via `__constructScpWithNativeForTests` at `new SCP()` time).
- **DID ownership + DoS cap on recovery / custody migration (red-hat RED-PR5-003/004).** `identity_execute_recovery` and `identity_execute_custody_migration` on `NapiScp` now reject DIDs absent from the bridge instance's identity registry with `SCP-IDENT-1020` / `SCP-IDENT-1024`. Without this gate any realm-local caller could drive unmetered recovery work on `crate::runtime()` against arbitrary DIDs. Both methods also enforce `MAX_CONTEXT_IDS_PER_{RECOVERY,MIGRATION} = 1024` at the FFI boundary; over-cap requests return `SCP-VALID-7120` before the orchestrator runs. The equivalent PyO3 and UniFFI surfaces inherit the same ownership gate through the shared identity registry.
- **NAPI crypto methods stay sync (bug-catcher HIGH).** Commit `3de6cbe30` flipped the TS wrappers for `identityExecuteRecovery` / `identityExecuteCustodyMigration` to `async` under the misreading that the Rust methods were async. They are not — the Rust side runs on `crate::runtime()` via `block_on`, matching every other sync bridge function. Round-2 (`78102c871`) reverted the TS wrappers back to sync; the SDK surface is `string` (not `Promise<string>`). The JSON payload remains the return type; callers parse it as needed.
- **Per-test `SCP` isolation in the TS integration suite.** The restored real-NAPI integration suite initially shared a single `new SCP()` + in-memory relay across every test in each `describe` via `beforeAll`/`afterAll`. Two tests (`identityExecuteCustodyMigration rejects an unknown target`, `identityExecuteRecovery rejects an unknown tier synchronously`) were only passing because fabricated `did:dht:z6Nope` DIDs happened to round-trip through the DID registry populated by earlier tests. Round-3 (`d8ffcdadf`) switched to `beforeEach`/`afterEach` with a fresh `SCP` + bridge + relay per test; the two affected tests now create real identities via `scp.identityCreate` so the validation branch they claim to exercise is actually reached. This is the canonical pattern documented in `.docs/migration/phase-4.md` — post-PR-5 the suite enforces it, not just recommends it.

Concurrency cap on recovery / migration: a per-instance **semaphore**
(`NapiBridgeInstance::recovery_semaphore`, cap =
`RECOVERY_CONCURRENCY_CAP`) bounds concurrent `block_on`-backed
orchestrator dispatches so a flood of valid-DID recovery or migration
requests cannot saturate the libuv worker pool
(RED-PR5-002 / BLACK-PR5-002). `try_acquire_owned` is non-blocking —
exhausted permits return `SCP-VALID-7140` immediately rather than
queue on the wait (a queued caller would still pin a libuv worker).
The 1024-entry `context_ids` cap and the semaphore compose: the first
bounds per-call amplification, the second bounds invocation
concurrency.

No round-3 findings remain open against §7.

### 7a. Post-merge integration with ADR-046 bridge parity + ADR-047 bridge symmetry

After §7 landed on the branch, `origin/main` advanced with three PRs that needed to integrate atomically with the façade-delete surface:

- **#1682** — ADR-046 bridge-parity harness + ADR-047 bridge-symmetry enforcement.
- **#1697** — retro review-fix consolidation.
- **#1699** — P0/P1 review follow-up.

The two workstreams touched the same bridge surfaces from opposite ends: §7 moved free-function façade exports to `Scp::*` instance methods, while ADR-046 added new parameters (`seed`, `signed_at_override`) and fields (`verifying_key_hex`) to those same façade functions. Integration required porting ADR-046's parity features onto §7's per-instance methods rather than resurrecting the façade. Scope of the merge integration:

**Identity construction — `verifying_key_hex` field.** The `Identity` struct in every non-WASM bridge gains a `verifying_key_hex: Option<String>` field (hex-encoded Ed25519 verifying-key bytes for the identity key, VM `#0` — the DID-deriving key, not `#active`). Chosen because the WASM bridge uses a simplified single-key model in production where the DID-deriving key *is* the signing key; exposing the identity key gives byte-exact parity across all four bridges under a deterministic `seed`. Populated at every constructor site across PyO3 (`PyIdentity::new` / `PyIdentity::from_document` factory methods, 8+ sites), NAPI (`NapiIdentityInner` literal, 13 sites), UniFFI (`Identity { ... }` literal, 7 sites), WASM (`WasmIdentity { ... }` literal, 8 sites). Populated via `custody.public_key(&identity.identity_key).await.ok().map(|pk| hex::encode(pk.as_bytes()))` — an ADR-046 stability contract, not an exposed API at the SDK layer (read via `identity.verifying_key()`).

**Identity creation — `testing_seed: Option<Vec<u8>>` parameter.** `Scp::identity_create(custody, testing_seed)` on every non-WASM bridge accepts an optional 32-byte deterministic RNG seed. When `Some(bytes)`, `InMemoryKeyCustody::from_seed_bytes(bytes)` replaces the default `OsRng`-backed `InMemoryKeyCustody::new()`, making subsequent `generate_keypair` calls produce byte-identical Ed25519 keys across bridges. Rejected with `SCP-VALID-7007` for length ≠ 32 bytes and with `SCP-VALID-7009` for non-`in_memory` custody (Platform/Software paths reject the parameter — seeded determinism is only meaningful for in-process testing custody).

Swift / Kotlin SDK wrappers expose `testingSeed: Data? = nil` / `testingSeed: ByteArray? = null` defaults so production callers retain the single-argument call shape. The name makes intent explicit at the call site: `scp.identityCreate(custody: "in_memory", testingSeed: seedBytes)` reads as a testing affordance rather than a production knob.

**SCPID signing — `signed_at_override: Option<u64>`.** `Scp::scpid_sign(identity, signing_key_id, challenge_json, signed_at_override)` accepts a Unix-millisecond timestamp that substitutes for the wall clock in the canonical hash. Only accepted when scp-core is built with the `testing` feature; production builds reject non-`None` values with `SCP-VALID-7008`. This affordance drives the cross-bridge parity harness's byte-exact SCPID signatures — two bridges signing the same challenge under the same seed with the same `signed_at_override` produce identical signatures. The feature gate is compile-time — a `testing`-enabled artifact reaching production is the threat model and is addressed by release-channel discipline (no `testing` feature on production wheels / jars / xcframeworks).

**§18.4.1 context_id alignment.** Main's fix to emit 64-char lowercase hex context IDs across all four bridges (`hex::encode(32 random bytes)`, matching PyO3's reference `generate_context_id`) is preserved in `Scp::context_create` on every non-WASM bridge. The UniFFI per-instance method regressed to `ctx-<uuid>` during the merge because PR 5 had authored the per-instance `Scp::context_create` before main's fix landed on free-function `context_create`; the regression was caught by the preserved `context_create_returns_active_context` test and fixed in the post-merge SDK follow-up commit.

**Enforcement alignment.**

- `scripts/check-call-invariants.py` rule `did-resolver-init-on-identity-create` expected callee `ensure_did_resolver_initialized`; NAPI and UniFFI had renamed to `_on` suffix (per-instance helper convention), PyO3 had not. Unified PyO3 on `_on` and updated the matrix rule's `required_callee`. Rule ID unchanged; `required_rule_ids_digest` unchanged — the rule-level contract is unchanged, only the implementation pattern tracked a rename.
- `scripts/bridge-aliases.json` PyO3 alias lists contained `py_*` free-function names; PR 5 renamed to PyScp method form. Extended each PyO3 alias list to include both forms (97 operations). Per-bridge symmetry check still independent — adding method-form aliases to PyO3 does not mask missing coverage in NAPI/UniFFI/WASM.

**Swift `ScpId` unbound closures.** The free `scpidSign` / `scpidVerify` UniFFI exports were deleted in PR 5 (per-instance `Scp::scpid_sign` / `Scp::scpid_verify` replace them, routing the Identity handle-affinity check + DID resolver through the caller's own `SCP`). `ScpId.unboundSign` / `unboundChallenge` / `unboundVerify` in `bindings/swift/Sources/SCP/Auth/ScpId.swift` consequently cannot delegate to the deleted free functions; they throw `SCP-IDENT-1046` pointing at `SCP.scpidSign` / `SCP.scpidChallenge` / `SCP.scpidVerify`. No consumer code in `Sources/` / `Tests/` / `examples/` depends on these closures — the exported `ScpId.sign(scp:identity:signingKeyId:challenge:)` / `ScpId.verify(scp:response:challenge:)` methods already require an explicit `SCP` parameter.

**Integration state at merge (this stack).** The Python harness driver rewrite and every helper runner rewrite (`bindings/python/tests/bridge_parity/helpers/{node,swift,kotlin}_bridge_runner/`) are completed in commits `fdd9524b0`, `409efd15c`, `0b381d3a9`, `7e8759bdc`, and `1d21ae68d` — the driver constructs `SCP` instances and calls `scp.identity_create(...)` / `scp.context_create(...)` / `scp.scpid_*(...)` through the per-instance surface; each helper runner drives the same per-instance methods on its bridge. Rust-side parity plumbing (seed, verifying_key_hex, signed_at_override) is live across all three non-WASM bridges. `scp-ffi-common::generate_context_id()` (added as part of this PR, `crates/scp-ffi/common/src/context_id.rs`) is the shared helper all four `Scp::context_create` implementations use, preventing the class of divergence this ADR documents — a regression in any single bridge would now require deleting the shared call, not silently re-rolling the 32-byte draw.

**Known parity regression — `transport_status` on UniFFI.** UniFFI's per-instance `Scp.transportStatus(manager: Arc<TransportManager>)` requires a non-optional `TransportManager` handle; PyO3's `PyScp::transport_status()`, NAPI's `Scp::transport_status()`, and WASM's equivalent keep the handleless probe that returns `{ connected: false, relay_url: None, latency_ms: None }` when no transport is attached. The parity harness's `transport_status_disconnected` op (`bindings/python/tests/bridge_parity/seed_operations.py:770-796`) is xfailed for `uniffi-kotlin` and `uniffi-swift` on this branch; PyO3/NAPI/WASM still compare exactly. To restore 4-bridge parity the resolution is to add a handleless `Scp::transport_manager_status()` to the UniFFI bridge that returns the same disconnected-state struct when no `TransportManager` has been attached — the handleless shape is a property of the disconnected state, not a capability gap, so the parity harness runs against the common surface without needing a relay fixture on the UniFFI runners. The alternative (teaching each UniFFI runner to construct a `TransportManager` before calling `transportStatus`) re-introduces bridge-specific fixture plumbing that the harness was built to avoid.

## Consequences

- **Tests parallel-safe on every bridge.** Per-test `SCP` fixtures eliminate `BRIDGE_LIFECYCLE_SERIAL`, per-test `beforeAll` in NAPI, and the module-scope poisoning on every SDK. pytest-xdist, Gradle parallel tests, and XCTest concurrency all work.
- **Multi-identity and multi-relay coexistence work.** A single process may hold multiple `SCP` instances, each with its own identity and its own relay connection. No shared mutable state leaks across them.
- **Handle misuse is caught at the boundary.** Cross-instance handle reuse returns `SCP-PERM-3030` immediately, rather than corrupting silently.
- **Shutdown is bounded and recoverable.** `shutdown(timeout)` drains outstanding work deterministically. Callers no longer deadlock on stuck tasks.
- **No deprecation window.** The free-function façade is deleted in PR 4. There is no one-release-cycle tolerance period; every call site migrates in the same change that removes the façade. SCP is pre-release with no external consumers, so the cost of dropping the sunset window is zero and the benefit is eliminating a migration that would have to happen anyway two releases later.
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
milliseconds in an unsigned 64-bit integer uniformly across all three
non-WASM bridges:

- **NAPI**: `u64`, exposed as JS `BigInt` (widened from `u32` in #1692).
- **UniFFI**: `u64`.
- **PyO3**: `u64` via Python `int`.

The user-facing API is uniform — seconds at the SDK layer in every language
(`TimeInterval` in Swift, `Duration` in Kotlin, `float` in Python, `number`
in TypeScript). Each SDK wrapper clamps non-finite and out-of-range inputs
to a safe representable maximum before crossing FFI (TypeScript uses
`Number.MAX_SAFE_INTEGER` ms; Swift uses `>= Double(UInt64.max) / 1000.0`
to avoid an IEEE-754 rounding trap at the exact boundary — round-3
bug-catcher finding).

The earlier NAPI/UniFFI asymmetry (`u32` on NAPI to avoid forcing JS
callers onto `BigInt`) was rejected in #1692 in favor of uniform
semantics. The cost of `BigInt` at the NAPI boundary for a shutdown
timeout is trivial — the TypeScript SDK wrapper always accepts a plain
`number` and coerces once before the FFI call — and the benefit of
cross-bridge uniformity (one code path, one cap, one invariant) outweighs
the ergonomic tax.

Any SDK caller passing a value larger than the clamp cap gets
deterministic clamping at the boundary, not silent truncation.

### ADR numbering disambiguation (ADR-043)

Two existing ADR-043 entries coexist in-tree:

- `.docs/adrs/phase-3.md` § "Scope Registration as Handle Convention"
- `.docs/adrs/phase-6.md` § "Protocol Constants Reclassification"

When this ADR or the plan references ADR-043, the intended sense is the **phase-3** one (Scope Registration as Handle Convention). The later duplicate will be renumbered in a separate chronicler follow-up — tracked out of band, not blocking this ADR.

### Related PR sequence

Phase 4 remainder is four sequential PRs:

1. **PR 1 — Foundation.** This ADR, the `SCP` class scaffold in all three bridges, `BridgeInstanceCore` trait + per-bridge concrete struct refactor, rename `BRIDGE_INSTANCE` → `DEFAULT_BRIDGE_INSTANCE`, deprecation scaffold on the free-function façade, `instance_id`-backed handle affinity, `shutdown(timeout)` signature change and plumbing. No singletons migrated yet — free functions still forward to the default instance.
2. **PR 2 — Migrations + deletions + #1646.** Move every remaining per-identity singleton into typed fields on its per-bridge struct. Delete `EMPTY_IDENTITY_REGISTRY`, `EMPTY_UCAN_REGISTRY`, `BRIDGE_LIFECYCLE_SERIAL`. Fix `flush_all_contexts_sync` (AC3 bugs). Exhaustive security-reviewer audit of every path reaching ContextManager state.
3. **PR 3 — Persistence + multi-relay + real UniFFI crypto.** [LANDED 2026-04-18.] Expose `SqliteStorage` via `SCP::with_storage`. Thread persistence provider through UniFFI `ContextManager::new()` (#1260). Make `resume()` async; restore contexts + reconnect transport using stored `pending_relay_url` (#1678). Wire real `MlsCryptoProvider` through UniFFI (#1342). Integration tests for multi-relay + suspend-kill-resume-restore. See **PR 3 actualized** section below for the final shape.
4. **PR 4 — Façade deletion + method migration + test codemod + enforcement.** (Re-scoped 2026-04-19.) (a) Every operation previously exposed as a free-function façade becomes an instance method on `PyScp` / `NapiScp` / `UniffiScp`. (b) Those methods are exposed in all four SDK wrappers. (c) Every free-function façade export is deleted, every `_deprecation.*` helper module removed, every `@available(*, deprecated)` / `@Deprecated` annotation stripped, `DEFAULT_BRIDGE_INSTANCE` `OnceLock` deleted in all three bridges, `SCP.default()` factory deleted in all four SDKs. (d) Every SDK test is rewritten to instantiate a fresh `SCP()` per test via the per-test fixture; the ~200-file mechanical codemod happens in this PR. (e) `scripts/check-no-default-in-tests.sh` gate and every `SCP-DEFAULT-INSTANCE-OK:` opt-in tag are deleted — the gate policed a façade that no longer exists. (f) This ADR is updated to reflect the outcome (façade DELETED in PR 4, no sunset window), and §3.7 / §22.3.1 / §22.3.5 carry the "per-identity/per-context within a single `SCP` instance" clarification. (g) Remaining CI gates stay in place and are verified to pass: `check-no-bridge-globals.sh` (with `DEFAULT_BRIDGE_INSTANCE` removed from the allowlist), `check-once-lock-ratchet.sh`, `check-no-fallback-registry.sh`, `check-handle-affinity.sh`. SDK capability matrix updated. CLAUDE.md enforcement-file list updated.

PR 2 and PR 3 touch independent axes and may run concurrently after PR 1. PR 4 depends on all prior.

### Spec clarifications to land in PR 4 (not this ADR)

- **§3.7 petnames.** Clarify that the per-identity petname cache is per-`SCP` instance. Two `SCP` instances holding the same identity converge via the identity-level sync protocol, not via a process-global cache. The spec does not mandate the cache; the current process-global is an implementation detail, not protocol.
- **§22.3.1 handle registries.** Clarify that handle registries are per-context within a given `SCP` instance — same as the existing semantics, just stated explicitly.
- **§22.3.5 scope registries** (ADR-043, phase-3 sense). Same clarification: per-context within an `SCP` instance.

None of these are breaking changes. They are disambiguations that were globally ambiguous and are now explicit.

### Updates to related ADRs (PR 1 scope)

- **ADR-021 (UniFFI Bridge).** Note that `SCP` is a first-class `uniffi::Object`; the 172 `#[uniffi::export]` functions that touch instance state become methods on `Scp`.
- **ADR-028 (Kotlin SDK).** Note that `NativeBindings` methods move onto `SCP`; `CoroutineBridge` refactors to own the `SCP` instance directly rather than wrapping sub-bridges.

## PR 3 actualized (2026-04-18)

PR 3 of the Phase 4 remainder — **Persistence + multi-relay reconnect + real UniFFI crypto** — has landed on branch `refactor/scp-phase4-persistence`. The decisions captured above remain binding; this section records how PR 3 was actually shaped, the breaking changes it introduced, and the issues it closed.

### Async `resume()` semantics (BREAKING CHANGE)

`BridgeInstanceCore::resume` is now `async fn` across the trait, the `CoreFields::resume` helper, and every per-bridge override. The lifecycle contract previously flipped only the `suspended` flag; it now chains real work on top of that flip: reconnect every URL in the pending set, then restore persisted contexts.

- `CoreFields::resume` — `pub async fn`; body still flag-only, with `reconnect_transport_if_pending` and `restore_all_persisted_contexts` invoked by per-bridge overrides.
- `PyScp::resume(&self, py)` / `scp_resume(py)` — PyO3 releases the GIL via `py.allow_threads(|| rt.block_on(async { ... }))`, matching the existing `shutdown` pattern.
- `Scp::resume` on NAPI — native `async fn`, driven by the Tokio worker pool.
- `Scp::resume` on UniFFI — `pub async fn`, surfacing as Kotlin `suspend fun` and Swift `async throws` on the generated bindings.

SDK wrappers match:

- Python: `async def resume(self)` — awaits the PyO3 async path.
- TypeScript: `resume(): Promise<void>` — both NAPI-native and WASM-mock bridges.
- Swift: `func resume() async throws` — forwards `try await`.
- Kotlin: `suspend fun resume()` — routed through `CoroutineBridge.ffiCallSuspend` (promoted from fire-and-forget `ffiCall`). `shutdown()` moved to the same path for the same reason.

**Error contract.** Reconnect failures surface as a new `LifecycleError::ReconnectFailed { url, reason }` variant. The first failure is returned; successfully-connected URLs stay in the pending set so callers may retry individually.

Lifecycle tests across all four SDKs converted to `#[tokio::test]` / the idiomatic async test form in each language.

### Multi-URL reconnect via `HashSet`

`CoreFields::relay_url: Mutex<Option<String>>` is replaced with `relay_urls: Mutex<HashSet<String>>`. `TransportManager` already supports multi-adapter routing; the single-URL state was artificially narrow.

New accessors on `CoreFields`:

- `add_relay_url(url)` — inserts into the pending set.
- `remove_relay_url(url)` — removes on explicit disconnect.
- `pending_relay_urls()` — snapshot for resume iteration.

The old `set_relay_url` / `clear_relay_url` / `pending_relay_url` trio is deleted. Each per-bridge `resume()` override iterates the set, reconnects each URL via `reconnect_transport_if_pending`, and returns `LifecycleError::ReconnectFailed { url, reason }` on the first failure.

`reconnect_transport_if_pending` builds a single `TransportManager::builder()` outside the loop, `add_adapter`s every successful reconnect, and calls `set_transport` once — preserving every reconnected adapter. An earlier draft constructed one `TransportManager::new(adapter)` per iteration and `set_transport`'d each; because `set_transport` replaces (not appends), only the last adapter survived. The corrected single-manager wiring matches the pre-suspend multi-relay invariant: if `TransportManager` carried N adapters before suspend, it carries N adapters after resume.

### Removal of `FfiBridgeCrypto` (closes #1342)

The UniFFI bridge no longer constructs a DID-less `ContextManager` with a no-op `FfiBridgeCrypto` stub. Every entry point that attaches a manager — `context_create`, `context_join`, `context_import`, `register_local_did`, `is_local_did` — now carries a local DID into `init_context_manager_with_did`, which wires `MlsCryptoProvider::new(did)`. UniFFI now matches the PyO3 and NAPI bridges.

Concrete deletions:

- `FfiBridgeCrypto` struct, `FFI_CRYPTO` static, `context_manager_crypto()` accessor — gone.
- `build_default_context_manager` / `build_default_context_manager_reusing_repo` and the DID-less `init_context_manager()` — gone.
- `context_manager_expect()` now returns `Result<&'static Arc<ContextManager>, ScpError>`; with no DID registered it fails with `ScpError::Context { code: CTX_2000, msg: "bridge not ready: no local DID registered" }`. Callers MUST invoke `register_local_did()` first. `register_local_did` itself now returns `Result<(), ScpError>` so validation failures surface directly.
- `context_close`'s `CloseOrchestrator` constructs a fresh `MlsCryptoProvider` scoped to the initiator's DID.
- `context_join` generates a real MLS key package via `generate_mls_key_package_bytes` (mirrors NAPI) — the stub used to accept `None`; real MLS rejects it.

Platform-specific key custody continues to flow through the existing `KeyCustodyProvider` callback — nothing new was wired there.

### Strategy B for #1342 — rationale vs. the master plan's literal wording

The master plan for #1342 described the fix as "wire real OpenMLS via UniFFI callback interface **or** direct Rust-side linking." Both approaches are valid in isolation; this section documents why the landed implementation (Strategy B: direct Rust-side `MlsCryptoProvider::new(did)` + required DID on UniFFI `ContextManager`) was the right call.

- **Strategy A (callback interface) would have been worse.** It would require a UniFFI callback trait that ferries MLS operations (`create_group`, `add_members`, `encrypt`, `decrypt`, `stage_commit`, `merge_staged_commit`, sender-key derivations, Welcome handling) across the FFI boundary into Swift/Kotlin. OpenMLS has no Swift or Kotlin implementation — the only real provider would be the Rust one — so callbacks would loop back across the FFI to call the same `MlsCryptoProvider` the Rust side already has. This is pure overhead (two FFI hops per MLS call) and adds a concurrency hazard: UniFFI callbacks are `Send + Sync` but the MLS state machine is not, so every call would need serialization the Rust-side provider already handles internally.
- **Strategy B (direct linking) matches the reference bridges.** The PyO3 bridge (`crates/scp-ffi/src/runtime.rs`) constructs `MlsCryptoProvider::new(local_did)` directly. The NAPI bridge (`crates/scp-ffi/napi/src/runtime.rs`) does the same. UniFFI now does the same: `init_context_manager_with_did(local_did)` constructs `MlsCryptoProvider::new(local_did)` at attach time. Three bridges, one pattern, zero divergence.
- **Making DID required closes the stub.** The old path allowed the bridge to attach a no-op `FfiBridgeCrypto` and defer DID resolution. That created two classes of `ContextManager` (DID-less vs. DID-bound) and forced every caller to handle the `None` case. Strategy B folds the DID requirement into the attach precondition, deleting `FfiBridgeCrypto` and making `register_local_did` the single entry point. Every `ContextManager` now carries a real MLS credential from the moment it exists.
- **Test shape confirms parity.** `crates/scp-testing/tests/multi_relay_uniffi_swift_kotlin_smoke.rs` exercises the UniFFI-through-Rust path end-to-end; behaviour matches `crates/scp-testing/tests/multi_relay_smoke.rs` (PyO3) and the NAPI multi-relay test. If Strategy A had been used, those tests would have to inject a Rust-provided callback harness to avoid the double FFI hop — effectively re-implementing Strategy B on top of a useless trait.

The master plan's "or direct Rust-side linking" clause is what landed; the callback path was rejected during execution on the grounds above. No scope was reduced — all #1342 acceptance criteria are covered, just via the second branch of the plan's original choice.

### `SqliteStorage` FFI exposure (closes #1491, closes #1260)

`StorageConfig` gains a `Sqlite { path: String, key: Vec<u8> }` variant across all three non-WASM bridges. The 32-byte SQLCipher key is validated at the boundary; length mismatches return `ScpError::Validation`.

- **UniFFI.** `#[derive(uniffi::Enum)]` generates a Swift enum and a Kotlin sealed class. Swift: `StorageConfig.sqlite(path:key:)`. Kotlin: `StorageConfig.Sqlite(path, key)`.
- **NAPI.** Accepts `{ type: "sqlite", path: string, key: string | Uint8Array }` — the `key` field is hex-decoded when a string is supplied, used raw when a `Uint8Array`.
- **PyO3.** `SCP.with_storage({"type": "sqlite", "path": str, "key": bytes})` — Python `bytes` for the key.

Wiring: `with_storage_py` / `with_storage_napi` / `with_storage_uniffi` open a `SqliteStorage`, wrap it in a `ProtocolRepositoryContextBridge`, and attach the resulting `Arc<dyn ContextPersistence + Send + Sync>` to `CoreFields::persistence` via the new `with_persistence_arc` constructor. The `init_context_manager*` family picks up the same shared `Arc` via `persistence_arc_clone()` and hands it to `ContextManager::with_persistence` wrapped in a bridge-local `ArcContextPersistence` adapter — so the `ContextManager`'s internal `Arc` and the `CoreFields` mirror point at the same `rusqlite::Connection`. One connection backs both the suspend/resume flush path and per-request persistence.

PyO3 additionally routes the same `Arc<SqliteStorage>` into the existing `StorageProvider` enum so identity, trust, MCP, and event log reads/writes share that connection instead of opening a second one.

NAPI falls back to the legacy in-memory `NapiBridgePersistence` when no shared provider is configured, preserving behaviour for callers that built their instance via `withStorage({type: "in_memory"})` or the default-instance path.

SDK convenience constructors:

- Swift: `SCP.withStorage(sqliteDir: URL, key: Data)` — forwards to `.sqlite(path:key:)`.
- Kotlin: `SCP.withSqlite(dir: File, key: ByteArray)` — companion factory on `SCP`.
- Python: `SCP(storage={"type": "sqlite", ...})` accepted directly.
- TypeScript: `SCP.withStorage({ type: "sqlite", path, key })` on both NAPI and WASM backends.

### Reference closures

PR 3 closes the following issues:

- **#1491** — `SqliteStorage` FFI exposure.
- **#1260** — UniFFI `ContextManager` persistence threading.
- **#1678** — Async `resume` + multi-relay reconnect.
- **#1342** — UniFFI real crypto; `FfiBridgeCrypto` deleted.

### Non-SCP handle `instanceId` getters — known low-risk enumeration surface

Every NAPI handle type (`NapiContextHandle`, `NapiIdentity`, `NapiUcanToken`, `NapiMcpServerHandle`, `NapiMcpClientHandle`, `NapiTestingHandle`, …) exposes a JS-visible `instanceId` getter via `#[napi(getter, js_name = "instanceId")]`. The getter returns the u64 as a JS string (u64 exceeds `Number.MAX_SAFE_INTEGER`) so the handle-affinity macro on the Rust side can read the value via `handle.instance_id()` — a separate inherent method used by `napi_check_handle!`.

The getter is **redundant with the Rust-side method for affinity enforcement** — the macro calls the inherent `instance_id()` method on the Rust type, not the JS property. The getter exists so JS-side test harnesses and diagnostic code can correlate handles to the `Scp` instance that minted them.

A defence-in-depth hardening would either:
- mark the getters `#[napi(getter, skip)]` so the JS property is invisible at runtime (the Rust-side affinity check still sees the u64), or
- gate the getter behind an authorisation check that verifies the caller holds the `Scp` instance that minted the handle.

Both impose friction on legitimate tooling (e.g. `handle.instanceId === scp.instanceId` assertions in SDK tests) without reducing the risk surface meaningfully: an attacker who can execute JS in-process already has FFI reach, so enumerating `instanceId` across handles yields no capability they do not already have.

Documented here so future security reviewers don't re-litigate: the getter stays. Any migration must coordinate with the SDK test harnesses and the handle-affinity macro. PR #1690 retro LOW.

### `check-no-bridge-globals.sh` widened to function-local sharing primitives (PR #1699 review follow-up)

The original ratchet walker ignored any `static` declaration at brace depth > 0 — the rationale was that function-local statics are "naturally scoped." A PR #1699 review correctly rejected that framing for the sharing primitives: a `static NETWORK: OnceLock<Mutex<…>>` inside a helper fn has the same `'static` lifetime, same single-init semantics, and same cross-invocation process-global behavior as a module-level one. Function scope changes only the namespace, not the sharing semantics.

The walker now scans function-local `static` declarations too, but only when their type starts with or contains one of the process-global sharing primitives — `OnceLock<…>`, `LazyLock<…>`, `Mutex<…>`, `RwLock<…>`, `parking_lot::Mutex<…>`, or `parking_lot::RwLock<…>`. These get a `COUNT_FN_LOCAL` tag (still counted against the same per-bridge ratchet total as module-level globals) or `ALLOW` if their name is on the allowlist. Function-local statics of naturally function-scoped types — atomics (`AtomicU64`, `AtomicBool`, …), `Cell`, `RefCell`, `std::sync::Once` init guards, thread-local macros — remain ignored.

The `NETWORK` slot in `crates/scp-ffi/napi/src/testing.rs` — a function-local `OnceLock<Mutex<Option<FullStackNetwork>>>` used by the cross-test-file full-stack harness — is allowlisted by name because the `testing` module is feature-gated behind `allow_in_memory_custody` and is never compiled into production builds. The doc-comment on the declaration carries the full rationale. Any future function-local sharing static in a bridge must either move onto the per-bridge instance struct or extend the allowlist with the same kind of justification; bumping the ratchet count alone is not a valid fix.
