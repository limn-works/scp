# Changelog

All notable changes to SCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-04-25

### Actor-per-context refactor (ADR-049)

Internal concurrency redesign of `crates/scp-runtime`. The
previously-existing `ContextManager` is gone; `Supervisor` is the new
authoritative state owner (see
`.docs/adrs/ADR-049-actor-per-context.md`). FFI bridges and SDK
wrappers are unchanged at the surface level; the rewrite is internal
to `scp-runtime`.

**Caller-visible behavioral changes:**

- **50ms coalesce-rollback semantics for non-authorization-downward
  state.** Per ADR-049 §9 and spec §17.15.1, persistence outside the
  authorization-downward set (any operation that transitions a
  member's authorization downward — UCAN issuance/attenuation/
  revocation, role assignment/demotion/blocklist updates, MLS epoch
  advance, sender-key rotation, event log append, KeyPackage
  consumption, saga phase transitions) is coalesced on a 50ms write
  window per actor. On actor crash, the in-flight coalesce window may
  roll back up to 50ms of non-critical state (participation counters,
  velocity trackers, receive buffer position, etc.).
  Authorization-downward operations remain sync-persisted with no
  rollback risk — see ADR-049 §9 for the full authorization-state
  persistence rule.
- **`Supervisor::shutdown_all_contexts` is now async.** The blocking
  `try_lock` cleanup pattern was replaced with awaited `lock().await`
  acquisitions so cleanup does not silently skip on contention. Sync
  callers (destructor / atexit hooks) use the new
  `Supervisor::shutdown_all_contexts_sync` wrapper.

References: ADR-049 §9 (coalesced persistence rule),
`.docs/specs/17-persistence-and-storage.md` §17.15.

## [Unreleased] - 2026-04-18

### Phase 4 PR 3 — Persistence + async resume + real UniFFI crypto

**Breaking changes — external SDK consumers migrating from PR 1 behavior:**

- **`SCP.resume()` is now async.** `BridgeInstanceCore::resume` became `async fn` (#1678) so per-bridge overrides can chain relay reconnect and persisted-context restoration on top of the suspended-flag flip. Callers must await / suspend:
  - Python: `await scp.resume()` (was synchronous)
  - TypeScript: `await scp.resume()` (returns `Promise<void>`)
  - Swift: `try await scp.resume()` (was synchronous `throws`)
  - Kotlin: `scp.resume()` inside a coroutine / suspend function (was blocking `ffiCall`)
  - Reconnect failures surface as `LifecycleError.ReconnectFailed { url, reason }` (new variant).
- **`StorageConfig` extended with SQLite (#1491, #1260).** New variant `Sqlite { path, key }` across PyO3, NAPI, UniFFI. WASM remains InMemory-only.
  - Python: `SCP(storage={"type": "sqlite", "path": str, "key": bytes})` — 32-byte key as Python `bytes`.
  - TypeScript: `SCP.withStorage({ type: "sqlite", path, key })` — `key` is hex `string` or `Uint8Array`.
  - Swift: `SCP.withStorage(sqliteDir: URL, key: Data)` convenience; also `StorageConfig.sqlite(path:key:)` directly.
  - Kotlin: `SCP.withSqlite(dir: File, key: ByteArray)` companion; also `StorageConfig.Sqlite(path, key)` directly.
- **UniFFI `ContextManager` requires a local DID before context ops (#1342).** `FfiBridgeCrypto` is deleted; UniFFI now constructs `MlsCryptoProvider::new(did)` exactly as PyO3 and NAPI do. Swift and Kotlin callers must invoke `scp.registerLocalDid(...)` before `context_create` / `context_join` / `context_import`. Calling a context operation before registration returns `ScpError.Context { code: "CTX_2000", msg: "bridge not ready: no local DID registered" }`.
- **Multi-relay reconnect via `HashSet` (#1678).** `CoreFields::relay_url: Mutex<Option<String>>` became `relay_urls: Mutex<HashSet<String>>`. Accessors replaced: `add_relay_url` / `remove_relay_url` / `pending_relay_urls` (was `set_relay_url` / `clear_relay_url` / `pending_relay_url`).

Closes #1342, #1260, #1491, #1678. See `.docs/adrs/ADR-048-scp-multi-instance.md` § "PR 3 actualized" for the full design commentary.

### Phase 4 PR 4 — Test codemod + enforcement + docs

- **Migration guide published** at `.docs/migration/phase-4.md`. Covers every breaking change landed in PR 1 → PR 3, the per-test `SCP` fixture recipe for Python / TypeScript / Swift / Kotlin, the `SCP-DEFAULT-INSTANCE-OK` opt-in tag, and the CI gate reference table.
- **New CI gate — `scripts/check-no-default-in-tests.sh`.** Fails the build if a test file calls a free-function façade (`scp_sdk.context_create(...)`, `.contextCreate(...)`, etc.) without an explicit `SCP-DEFAULT-INSTANCE-OK: <reason>` tag on the offending line or within 2 lines above. Guards the per-test-fixture invariant from ADR-048 §Decision 3. Exempts deprecation-verifying tests by filename.
- **New CI gate — `scripts/check-no-fallback-registry.sh`.** Greps for the `EMPTY_IDENTITY_REGISTRY` / `EMPTY_UCAN_REGISTRY` identifiers deleted in PR 2. Accepts occurrences inside comments (they remain as historical context); fails on any non-comment use. Regression guard for the silent "bridge not initialized" data-loss pattern described in ADR-048 §Context.
- **CI wiring.** `check-no-bridge-globals.sh`, `check-no-fallback-registry.sh`, and `check-handle-affinity.sh` are now required status checks alongside the existing `cross-layer`, `protocol-sync`, and `sdk-coverage` gates. `check-no-default-in-tests.sh` is staged in-tree but NOT yet wired to CI — it fires on ~500 pre-existing call sites that the per-test SCP fixture codemod (next PR) migrates to the new fixture pattern. The gate lights up in the codemod PR once those call sites move or carry the `SCP-DEFAULT-INSTANCE-OK` opt-in tag.
- **SDK capability matrix.** Added explicit rows for `scp_new`, `scp_default` (deprecated), `scp_with_storage_in_memory`, `scp_instance_id`, `shutdown_timeout`. The pre-existing `suspend` / `resume` / `with_storage_sqlite` / `add_relay_url` rows already documented the async / multi-relay surface.
- **CLAUDE.md enforcement file list updated.** The four gate scripts, `ratchet/once-lock-count.json`, and `sdk-capability-matrix.json` are all flagged as "modify only to expand coverage" so future agents can't silently weaken them.

No runtime or semantic changes. Closes #1549.

## [Unreleased] - 2026-03-16

### Security

- PCS break fixed (#1250) — `recovery_advance_epoch` now performs real MLS epoch advance
- Relay swap attack fixed (#1222) — leaf hash verification in `RelayBlobColdProvider`
- Kotlin JSON injection fixed (#1203) — `buildJsonObject` replaces string concatenation
- PSK nonce hardened (#1246) — random nonce replaces deterministic SHA-256
- Checkpoint signature verification (#623) — Ed25519 verification before comparison
- JCS compliance (#1252) — RFC 8785 canonical JSON for all hashing paths
- UCAN capability URI format (#1293) — fixed resource/action split mismatch across all 5 bridges
- MLS crypto snapshot Debug redaction (#706) — prevent key material exposure in logs
- Mutex poison partial state prevention (#712) — MLS `restore_crypto_state` atomicity
- Webhook replay protection and error code collision fixes (#1237)
- Decryption failures return 404 to prevent oracle (#1291)
- X-Forwarded-For trusted-proxy SHOULD upgraded to MUST (#1292)

### Added

- **WASM MLS encryption** (#602) — browser clients can now participate in encrypted contexts
- **Provenance event log recording** (#586) — `ProvenanceAttached`/`ProvenanceReceived` events across all 4 FFI bridges
- **Broadcast content delivery** — `BroadcastContent`, `ContentMetadata`, `ContentPath`, `MimeType` types (SCP-287)
- **Path-indexed projection endpoint** with atomic deploys (SCP-288, SCP-289)
- **Trust aggregation** exposed across all 4 bridges and SDKs (#596)
- **Economic governance** exposed across all 4 bridges (#613)
- **Media subsystem** exposed through FFI bridges (#597)
- **Bidirectional consent protocol** across all 4 bridges and SDKs (#579)
- **Invitation evaluation pipeline** with WASM security checks (#614)
- **Provenance privacy functions** across all 4 bridges (#585)
- **Bridge subsystem operations** through PyO3 bridge (#616)
- **MCP operations** exposed through UniFFI bridge for Swift/Kotlin (#591)
- **Tool session and cross-context invocation** wrappers for TypeScript and Kotlin (#526)
- **SCPID auth wrappers** for all 4 SDKs (#1058, #1059)
- **Identity advanced operation** test coverage across all SDKs (#428)
- **Governance pipeline and context lifecycle** methods exposed through FFI (#559)
- **MetadataRecord and ContextTemplate inspection** exposed through FFI (#615)
- **DegradedMode** with graceful degradation behavior (#606)
- **Participation types** added to TypeScript SDK with WASM bridge (#426)
- **Broadcast unblock** implemented across all layers (#617)
- **Min protocol version** added to `ContextParams` per spec section 13 (#607)
- **MLS group state and sender key persistence** across restarts (#645)
- **Encryption at rest** via sealed `EncryptedStorage` trait (#695)
- **Economic policy** set/get exposed across all FFI bridges and SDKs (#713)
- `cargo deny` configuration for dependency auditing

### Fixed

- **NAPI backend**: 82 tests passing (from 33), identity registry fallback, `MemberRole` case, DID resolver seeding (#1144, #1236)
- **Python SDK**: all 4 examples updated to match post-refactor API (#1297)
- **UCAN spec documentation**: two-tier validation design clarified (#1281)
- UCAN revocation pipeline wired with authorization and event logging (#499)
- `ToolCost` aligned with spec section 5.4.1 — renamed fields, added currency (#934)
- Error code harmonization across PyO3/UniFFI/NAPI/WASM bridges (#537)
- WASM sequence field harmonized to f64 matching NAPI (#1022)
- Swift `Context.lastError` stored instead of discarded (#541)
- Swift concrete `ContextHandle` in bridge function typealiases (#1018)
- Kotlin `toolVerifyResult` changed from Boolean to String (#1010)
- Kotlin `identityHandle` added to `ScpContextHolder` and `rememberScpContext` (#1009)
- TypeScript broadcast state preserved in mock `contextImport` (#1007)
- TypeScript `ucanToken` made required in `Context.invokeTool` (#745)
- TypeScript JSON.parse calls wrapped with safe error handling (#681)
- NAPI `PascalCase` `ParsedAddress` variant tags per spec (#737)
- WASM `DID` validation added to `context_leave` (#740)
- WASM `ucan_token` passed through `tool_invoke` bridge (#554)
- Governance timeout task with deadlock detection (#581)
- Sync TOCTOU race eliminated in reset request nonce tracking (#572)
- Sync mutual removal check in governance conflict resolution (#576)
- Context version check moved before crypto ops in `join_context` (#715)
- Context TTL expiry errors propagated with retry and observability (#612)
- Event log accepts pruned logs on restore (#705)
- Forward-compatible deserialization and FFI timestamp guards (#593, #538)
- Outbound queue ordering and bound enforcement (#709)
- Provenance rejects empty context IDs in discovery method parsing (#741)
- `SnapshotCodecFailed` renamed, `reconcile_epoch` returns Failed for unknown epoch (#1179, #1180)
- `Retry-After` field added to `InterfaceRateLimited` error (#1110)
- Typed `Capability` enum in `check_media_capability` replaces string comparison (#1042)
- Persistent `SenderKeyStore` in `bridge_create_shadow` (#539)
- NAPI `HANDLE_COUNT` underflow prevention (#1263)
- Envelope `deny_unknown_fields` removed from wire types per spec (#723)
- Event log per-entry keys for O(1) append persistence (#710)
- `ContextSnapshot` clone eliminated in persist (#711)

### SDK Validation

- **Kotlin**: 227 tests pass, detekt clean
- **Swift**: 437 tests pass, SwiftLint/SwiftFormat clean
- **Python**: 488 tests pass, ruff clean
- **TypeScript**: NAPI backend 82 tests pass, type checks clean

## [0.1.0] - 2026-03-11

Initial release of the Shared Context Protocol SDK.

### Added

- **Identity**: DID-based cryptographic identity with `did:dht` and `did:web` methods
- **Contexts**: Bounded, encrypted interaction spaces with MLS group encryption
- **Governance**: 4-engine governance system with 28 action types
- **Trust**: Behavioral fact statements, contextual trust scoring, content access control
- **UCAN**: Capability-based authorization with delegation chains
- **Transport**: Native relay protocol with 17 adapter targets across 3 tiers
- **Provenance**: Merkle event log with cryptographic audit trail
- **Discovery**: Context discovery, search, and federation
- **Media**: Media key derivation and signaling
- **MCP Bridge**: Model Context Protocol integration for AI agent connectivity

### SDK Packages

- **Rust**: `scp-core`, `scp-transport`, `scp-platform`, `scp-mcp` on crates.io
- **Python**: `scp-python` on PyPI
- **TypeScript**: `@limn-works/scp-ts` on npm (WASM + native NAPI addon)
- **Kotlin**: `works.limn:scp-kt` and `works.limn:scp-kt-android` on Maven Central
- **Swift**: `SCP` via SwiftPM (GitHub Releases)
