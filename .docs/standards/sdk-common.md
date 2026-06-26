# SDK Common Standards

Cross-language coding standards for all SCP SDK implementations. Every language-specific standards file references this document. For project structure, FFI strategy, naming conventions, versioning, and conformance testing, see `.docs/scaffold/shared.md`.

## Error Hierarchy

All SDKs implement the same error hierarchy. Language-specific idioms (exceptions, Result types, error interfaces) differ, but the categories are identical.

```
ScpError (root)
├── IdentityError        — DID creation, resolution, key rotation failures
├── ContextError         — Context lifecycle (create, join, leave, close) failures
├── PermissionError      — UCAN capability validation failures (Python: `UcanPermissionError` to avoid shadowing `builtins.PermissionError`)
├── CryptoError          — Encryption, decryption, signature failures
├── TransportError       — Network, relay, connection failures
├── ToolError            — Tool registration, invocation, verification failures
└── ValidationError      — Input validation, schema, parameter failures
```

### Error requirements

- Every error includes a human-readable message and a machine-readable error code
- Error codes are stable across SDK versions (for programmatic handling)
- Errors propagate context: what failed, why, and what to do about it
- Crypto errors never leak key material or internal crypto state in messages

### Error code format

`SCP-{CATEGORY}-{NUMBER}` where category matches the hierarchy above:

| Category prefix | Range |
|-----------------|-------|
| `SCP-IDENT-` | 1000-1999 |
| `SCP-CTX-` | 2000-2999 |
| `SCP-PERM-` | 3000-3999 |
| `SCP-CRYPTO-` | 4000-4999 |
| `SCP-TRANS-` | 5000-5999 |
| `SCP-TOOL-` | 6000-6999 |
| `SCP-VALID-` | 7000-7999 |
| `SCP-STORAGE-` | 8000-8999 |
| `SCP-ATTEST-` | 9000-9999 |
| `SCP-MCP-` | 10000-10999 |
| `SCP-GOV-` | 11000-11999 |
| `SCP-ECON-` | 12000-12999 |
| `SCP-SAGA-` | 13000-13999 |

### Registered SCP-SAGA- codes (cross-context tool-invocation saga, §6.2.4)

The `SCP-SAGA-` band (`13000-13999`, ADR-049 §3a) is partitioned into
sub-blocks by *which layer* raises the error, so a code is unique to one
distinct condition and `grep`-disambiguates a log line to a single call site.
`check-error-codes.sh` only range-checks the band; uniqueness within the band
is maintained by keeping each distinct error's number disjoint from every other
distinct error's number. When adding a new error, take the next free number
**inside the owning sub-block** — never reuse a number assigned to a different
condition, even across files.

| Sub-block | Owner | Purpose |
|-----------|-------|---------|
| `13000-13009` | `scp-protocol` `cross_context_saga.rs` | Saga-type signing / verification (pure, sync) |
| `13010-13099` | `scp-runtime` saga handler + supervisor FSM | Prepare / Commit / Abort phase coordination |
| `13100-13999` | *(reserved)* | Future cross-context saga families |

Within `13010-13099`, the handler (`actor/handlers/saga.rs`, the per-context
authorization + freshness + Commit-B execute/settle path) holds `13010-13049`,
and the supervisor (`supervisor/supervisor.rs`, the cross-actor FSM driver)
holds `13050-13099`, so the two layers never contend for the same number.

| Code | Layer | Condition |
|------|-------|-----------|
| `SCP-SAGA-13000` | protocol | Canonical preimage construction exceeded the length-prefix ceiling |
| `SCP-SAGA-13001` | protocol | Ed25519 saga signature failed verification |
| `SCP-SAGA-13002` | protocol | Malformed Ed25519 verifying key |
| `SCP-SAGA-13010` | handler | Caller lacks `tool:interface` capability (outbound) |
| `SCP-SAGA-13011` | handler | Caller not in outbound `allowed_callers` |
| `SCP-SAGA-13012` | handler | `ucan_proof_id` not resolvable in target proof store |
| `SCP-SAGA-13013` | handler | UCAN re-validation failed (confused-deputy re-bind) |
| `SCP-SAGA-13014` | handler | `target_context_id` mismatch |
| `SCP-SAGA-13015` | handler | Inbound policy requires a spending UCAN but none was presented |
| `SCP-SAGA-13016` | handler | Tool not found in target registry |
| `SCP-SAGA-13017` | handler | Input schema specificity floor not met |
| `SCP-SAGA-13018` | handler | Invocation timestamp outside §9.14 skew tolerance |
| `SCP-SAGA-13019` | handler | Invocation nonce already seen in target dedup cache (replay) |
| `SCP-SAGA-13020` | handler | Re-derived chain depth exceeds `max_chain_depth` |
| `SCP-SAGA-13021` | handler | Input does not conform to registered schema |
| `SCP-SAGA-13023` | handler | Per-interface §6.2.0.2 rate limit exceeded |
| `SCP-SAGA-13024` | handler | Per-caller §6.2.0.2 rate limit exceeded |
| `SCP-SAGA-13025` | handler | Caller role not in inbound `allowed_source_roles` |
| `SCP-SAGA-13026` | handler | Per-interface §6.2.0.2 INBOUND rate limit exceeded at Prepare-B |
| `SCP-SAGA-13027` | handler | Configured inbound rate exceeds the cache-eviction-safe ceiling (§6.2.4 sizing-vs-ceiling) |
| `SCP-SAGA-13030` | handler | Commit-B reserve found no staged cross-context invocation |
| `SCP-SAGA-13031` | handler | Commit-B settle found no staged cross-context invocation |
| `SCP-SAGA-13032` | handler | Commit-B tool output is not valid JSON |
| `SCP-SAGA-13033` | handler | Commit-B receipt output JCS canonicalization failed |
| `SCP-SAGA-13034` | handler | Commit-B receipt signing failed |
| `SCP-SAGA-13035` | handler | Commit-B receipt serialization failed |
| `SCP-SAGA-13036` | handler | Divergence-marker signing failed |
| `SCP-SAGA-13037` | handler | Divergence-marker serialization failed |
| `SCP-SAGA-13038` | handler | Saga phase reached the wrong dispatch helper |
| `SCP-SAGA-13050` | supervisor | Initiator is not a member of the named caller context (caller-axis authorize-before-reserve) |
| `SCP-SAGA-13051` | supervisor | Prepare — `CrossContextToolInvocation` reached `start_saga` without an executor context |
| `SCP-SAGA-13052` | supervisor | Prepare-A — caller context is not a co-resident actor |
| `SCP-SAGA-13053` | supervisor | Prepare-B — target context is not a co-resident actor |
| `SCP-SAGA-13054` | supervisor | Commit — `CrossContextToolInvocation` reached `start_saga` without an executor context |
| `SCP-SAGA-13055` | supervisor | Commit-B — target context is not a co-resident actor |
| `SCP-SAGA-13056` | supervisor | Commit-B — executor already consumed but no output stashed (coordinator bug) |
| `SCP-SAGA-13057` | supervisor | Commit-B — cross-context tool executor failed |
| `SCP-SAGA-13058` | supervisor | Commit-B — tool output is not serializable |
| `SCP-SAGA-13059` | supervisor | Commit-A — no held reservation and witness absent (Commit-A did not durably land) |
| `SCP-SAGA-13060` | supervisor | Commit-B settle — target context is not a co-resident actor |
| `SCP-SAGA-13061` | supervisor | Commit-A — caller context is not a co-resident actor |
| `SCP-SAGA-13062` | supervisor | No established interface for the (caller, target, tool) triple (target-axis authorize-before-reserve) |
| `SCP-SAGA-13063` | supervisor | Commit — target receipt missing for saga |
| `SCP-SAGA-13064` | supervisor | Commit — target receipt signature invalid |

### Registered SCP-ATTEST- codes

| Code | Description |
|------|-------------|
| `SCP-ATTEST-9001` | Device attestation provider call failed (Play Integrity API error) |
| `SCP-ATTEST-9006` | Attestation verification requires raw JSON, which is absent |
| `SCP-ATTEST-9010` | Identity link attestation create bridge function not yet exported |
| `SCP-ATTEST-9011` | Identity link attestation list bridge function not yet exported |
| `SCP-ATTEST-9012` | Identity link attestation remove bridge function not yet exported |
| `SCP-ATTEST-9013` | Identity link attestation renew bridge function not yet exported |
| `SCP-ATTEST-9014` | Identity link attestation verify bridge function not yet exported |
| `SCP-ATTEST-9015` | Attestation JSON bytes are not valid UTF-8 |
| `SCP-ATTEST-9016` | Attestation list JSON bytes are not valid UTF-8 |
| `SCP-ATTEST-9017` | Failed to re-serialize attestation to UTF-8 JSON |
| `SCP-ATTEST-9018` | Cryptographic-class verification method not verifiable via browser fetch |

### SCP-IDENT-1017 and its cross-bridge contract

This section documents `SCP-IDENT-1017` (missing signing custody) and the
per-bridge contract for how that one condition surfaces across the bridges. It
is **not** the full registry of `SCP-IDENT-` codes — other `SCP-IDENT-` codes
exist (for example, the pseudonym-derivation family `SCP-IDENT-1054`..`1057`)
and are documented with their own features.

| Code | Description |
|------|-------------|
| `SCP-IDENT-1017` | Operation requires retained signing custody (identity loaded externally with no retained custody, or handle is sign-only). Surfaced by handle-borne bridges for UCAN **mint** (NAPI + UniFFI), event-log **checkpoint** (NAPI + UniFFI), and **broadcast publish** (NAPI + UniFFI). UCAN **delegate** surfaces `SCP-IDENT-1017` on **UniFFI only**: NAPI resolves the delegator key from the identity registry and surfaces `SCP-IDENT-1001` on a registry miss (same structural reason as PyO3), so NAPI delegate does **not** surface `SCP-IDENT-1017`. |

**Cross-bridge note (native bridges).** PyO3 surfaces the analogous failure as `SCP-IDENT-1001` (registry-based key resolution per ADR-048 §7 — a registered identity always retains custody, so the "registered-but-no-custody" condition cannot arise); NAPI's UCAN **delegate** path is registry-based for the same structural reason and surfaces `SCP-IDENT-1001` as well (see the table above). On the native bridges (PyO3, NAPI, and UniFFI → Swift / Kotlin / TS-via-NAPI), consumers that catch the `IdentityError` category are safe for the missing-custody condition; only code that switches on the exact code string must account for the per-bridge code splits described above.

**WASM note (per signing path).** WASM maintains a DID-keyed `IDENTITY_REGISTRY` holding `OsRng`-generated keypairs (the private key never crosses FFI, ADR-006), so it *can* sign in-Rust where the registry has the key. The three signing paths nonetheless diverge by *path*, not as one uniform code:

- **UCAN mint / delegate** → `SCP-PERM-3000` (`UcanPermissionError`, capability-absent per ADR-034). The Rust side returns this immediately and defers UCAN signing to JS-side key custody (`WebCrypto`/`SubtleCrypto`). This is the **only** path where the `SCP-PERM-3000` claim holds — and it is a distinct condition from the native bridges' missing-custody `IdentityError`, so a WASM consumer must handle `UcanPermissionError` / `SCP-PERM-3000` separately; catching `IdentityError` alone does **not** cover it.
- **Event-log checkpoint** → signs **in-process** with the identity's `#active` key resolved from the DID-keyed `IDENTITY_REGISTRY`, returning a *successful signed* checkpoint carrying both the Ed25519 `signature` and the canonical `signing_payload_hash` — identical to the native bridges (ADR-048 §7b RESOLVED). The path fails closed in two distinct cases: if the DID is **not present** in the local registry it surfaces `SCP-IDENT-1001` (identity-not-found); if the DID **is registered** but the record retains no signing key (a `Resolved` DID-resolution-only handle) it surfaces `SCP-IDENT-1028` (registered-but-no-retained-custody). Both are `IdentityError`-category; neither raises `SCP-PERM-3000` (or a JS-custody deferral) on this path.
- **Broadcast publish** → **no in-Rust custody gate**. The `SCP-PERM-3000` errors WASM raises on this path are suspended-write and non-author authorization checks, a different condition entirely — not a missing-custody signal.

## Stub and Placeholder Policy

Code that does not fully implement its documented contract (acceptance criterion, ADR spec, or trait method) is a **stub**. Stubs are tolerated during phased implementation but must be traceable to the planning system.

### Requirements

1. **Every stub must reference a PRD story ID** in its doc comment or inline comment. The story must have acceptance criteria that, when met, will remove the stub. Example: `// Stub — see SCP-217 for storage wiring`.
2. **No silent stubs.** A function that returns a placeholder value (e.g., hardcoded default, empty result, reconstructed-from-args) without documenting the gap is a bug, not a stub.
3. **Stories marked "done" must have zero stubs** against their acceptance criteria. If a criterion is unmet, the story status must be `in_progress` or `pending` with a `blockedBy` reference.

### Enforcement

| Language | Mechanism |
|----------|-----------|
| Rust | `clippy::todo = "deny"`, `clippy::unimplemented = "deny"` (compile-time). Inline `// Stub —` comments reference story IDs (review-time). |
| Kotlin | detekt `ForbiddenComment` rule with `TODO`, `FIXME`, `HACK` values (CI). |
| Python | ruff `FIX` rules (`FIX001` through `FIX004`) for `TODO`, `FIXME`, `HACK`, `XXX` (CI). |
| Swift | SwiftLint `todo` rule (CI). |
| TypeScript | ESLint `no-warning-comments` rule (CI). |

All languages: PR review must verify that any function described as a stub in code comments has a corresponding PRD story with `status != "done"`.

## Async Patterns

All SCP SDK operations involving I/O (network, storage, crypto operations) are async. Each language uses its native async mechanism.

| Language | Async mechanism | Runtime | Sync wrapper pattern |
|----------|-----------------|---------|----------------------|
| Rust | `async fn` → `Future` | tokio | `tokio::runtime::Runtime::block_on()` |
| Python | `async def` → coroutine | asyncio | Background thread via `run_coroutine_threadsafe()` (see `python.md`) |
| TypeScript | `async function` → `Promise` | Event loop (browser/Bun/Node) | N/A (always async) |
| Swift | `async` → structured concurrency | Swift concurrency | `Task { await ... }.value` (rare) |
| Kotlin | `suspend fun` → coroutine | kotlinx.coroutines | `runBlocking { }` |
| Go | Synchronous with channels | goroutines | N/A (synchronous API, channels for streaming) |
| C# | `async Task<T>` | .NET task scheduler | `.GetAwaiter().GetResult()` (rare) |
| Java | `CompletableFuture<T>` | ForkJoinPool / virtual threads | `.get()` / `.join()` |

### Streaming return types

`Context.receive()` (and equivalents) returns a language-appropriate async stream. See `.docs/scaffold/shared.md` §Streaming Types for the full mapping. Summary:

| Language | `receive()` return type |
|----------|------------------------|
| Rust | `Pin<Box<dyn Stream<Item = Message> + Send>>` |
| Python | `AsyncIterator[Message]` |
| TypeScript | `AsyncIterable<Message>` |
| Swift | `AsyncSequence` |
| Kotlin | `Flow<Message>` |
| Go | `<-chan Message` |
| C# | `IAsyncEnumerable<Message>` |
| Java | `Flow.Publisher<Message>` (Reactive Streams) |

## Resource Lifecycle

SCP objects hold crypto state (MLS groups, key material, WebSocket connections) that must be properly released. Each language uses its idiomatic resource management pattern.

| Language | Pattern | Applied to |
|----------|---------|------------|
| Rust | `Drop` trait | `ContextHandle`, `Identity`, `TransportManager` |
| Python | `async with` (context manager) | `Context`, `Identity`, transport connections |
| TypeScript | `using` / `Symbol.dispose` (Explicit Resource Management) | `Context`, `Identity` |
| Swift | `deinit` + explicit `close()` | `Context`, `Identity` |
| Kotlin | `use { }` / `Closeable` | `Context`, `Identity` |
| Go | `defer ctx.Close()` / `io.Closer` | `Context`, `Identity` |
| C# | `await using` / `IAsyncDisposable` | `Context`, `Identity` |
| Java | `try-with-resources` / `AutoCloseable` | `Context`, `Identity` |

### Lifecycle invariant

When a resource goes out of scope or is disposed:
1. Leave any active contexts (sends `MemberLeft` event)
2. Destroy local key material (sender keys, MLS state)
3. Close transport connections
4. Flush pending events to the event log

Destruction of key material is immediate and irreversible. This is by design — SCP's security model depends on timely key destruction.

### Cleanup error handling

If any cleanup step fails (e.g., network unreachable when leaving a context), the resource MUST still complete local cleanup (key destruction, handle release). Errors during cleanup are logged but never propagated as exceptions — callers must not be penalized for disposing resources. The invariant: after dispose returns, all local state is released regardless of remote operation outcomes.

## Concurrency Model

All public handle types (`Identity`, `ContextHandle`/`Context`, `TransportManager`) are safe to share across threads and tasks. Individual operations are serialized internally — concurrent sends on the same context are safe and deliver in call order.

| Language | Guarantee | Mechanism |
|----------|-----------|-----------|
| Rust | `Send + Sync` | Interior `Arc<Mutex<_>>` or `Arc<RwLock<_>>` on mutable state |
| Python | Safe across `asyncio` tasks on the same event loop | GIL + interior locking in Rust core via PyO3 |
| TypeScript | Single-threaded event loop; safe across concurrent promises | N/A (no true concurrency) |
| Swift | `Sendable` | Actor isolation or `@unchecked Sendable` with interior locking |
| Kotlin | Safe across coroutines | Interior `Mutex` in Rust core via UniFFI |
| Go | Safe for concurrent use from multiple goroutines | Interior locking in Rust core via cgo |
| C# | Thread-safe | Interior locking in Rust core via P/Invoke |
| Java | Thread-safe | Interior locking in Rust core via JNA |

**Invariant:** No SDK user should ever need an external lock to use SCP types safely. If a data race is possible without user-side synchronization, the SDK has a bug.

## Context Creation

Context creation has two paths: template-based (primary) and explicit params (advanced). Both produce identical `ContextHandle` objects. See spec §5.12 for protocol-level template definitions.

Construction follows the unified config-object pattern (`.docs/standards/construction.md`, ADR-052): all five SDKs — Rust included — pass a single `ContextConfig` whose `creation: ContextCreation` field makes the template-vs-explicit choice a required enum (`Template { template, peer }` | `Explicit { ceiling, roles, governance, memory_scope }`). The previous Rust fluent `create_context().template().build()` builder is replaced so that every language uses the same options-object shape.

### Template-based creation (primary path)

All SDKs expose template-based context creation as the default. The template handles parameter selection; the caller provides only what varies (peer, TTL, tools for templates that allow them).

> **Bilateral `peer` and the invitation step.** Supplying `peer` names the counterparty to invite. The invitation/Welcome-delivery that actually adds the peer is delivered by a higher SDK layer; the core creation entry builds only the creator's local context. Until invitation delivery is wired, a `peer`-bearing config is **rejected loud** at the core entry (a typed `BilateralPeerNotSupported` error) rather than silently accepted-and-ignored — a supplied field is never dropped. The example below shows the target invitation surface; create with `peer` omitted to obtain the creator-local context today.

```
// Rust
let ctx = sdk.create_context(ContextConfig {
    ttl: Some(Duration::from_secs(300)),
    ..ContextConfig::defaults(ContextCreation::Template {
        template: Template::BilateralEphemeral,
        peer: Some(bob_did.clone()),
    })
}).await?;

// Python
ctx = await sdk.create_context(
    template="bilateral-ephemeral",
    peer=bob_did,
    ttl=timedelta(minutes=5),
)

// TypeScript
const ctx = await sdk.createContext({
    template: "bilateral-ephemeral",
    peer: bobDid,
    ttl: { minutes: 5 },
});

// Swift
let ctx = try await sdk.createContext(
    template: .bilateralEphemeral,
    peer: bobDID,
    ttl: .minutes(5)
)
```

### Explicit params (advanced path)

For contexts that don't fit a well-known template. The caller specifies all parameters. No template ID is attached to the context metadata.

```
// Rust
let ctx = sdk.create_context(ContextConfig {
    ttl: Some(Duration::from_secs(3600)),
    tools: vec![recipe_search, nutrition_lookup],
    ..ContextConfig::defaults(ContextCreation::Explicit {
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite, Capability::ToolInvokeAll],
        roles: vec![admin_role, member_role, observer_role],
        governance: Governance::SingleAdmin,
        memory_scope: MemoryScope::Summary,
    })
}).await?;
```

### Bilateral shorthand

For bilateral templates (`bilateral-ephemeral`, `bilateral-persistent`, `coordination`), the SDK accepts a peer DID and handles the invitation internally:

1. Creates the context (MLS group, sender key, event log)
2. Bundles context metadata + MLS Welcome message into a single transport delivery
3. Sends to the peer
4. Returns the `ContextHandle` immediately (context is `Active` from the creator's perspective)

The peer receives everything needed to evaluate and join in one message. If the peer has an auto-accept policy that matches, the join is automatic. If not, the peer's agent is prompted.

### Auto-accept policies

SDKs implement local auto-accept policy evaluation for incoming context invitations. Policies are configured per-identity and stored locally (never transmitted).

```
// Rust
sdk.set_auto_accept_policy(AutoAcceptPolicy {
    template: Template::BilateralEphemeral,
    from: TrustRequirement::KnownDid(vec![alice_did]), // explicit allowlist — the only trigger
    max_ttl: Some(Duration::from_secs(600)), // ≤10 minutes
    rate_limit: Some(Rate::per_hour(5)),     // Max 5 auto-accepts/hour
});

// Python
sdk.set_auto_accept_policy(
    template="bilateral-ephemeral",
    trust=TrustRequirement.known_did([alice_did]),  # explicit allowlist — the only trigger
    max_ttl=timedelta(minutes=10),
    rate_limit=Rate.per_hour(5),
)
```

**No default:** absent an explicit, human-configured policy, every invitation prompts the agent/human (default-deny). `known_did` is the only auto-accept trigger; co-membership and discoverability are not trust signals.

**Hard constraint (all SDKs, non-overridable):** Auto-accept policies NEVER apply to contexts whose ceiling includes any tool-related capability (`ToolInvokeAll`, `ToolInvokeSpecific`, `ToolRegister`). Tool-bearing contexts always require explicit confirmation. This is enforced in the SDK and cannot be disabled by configuration.

### Auto-accept persistence

Auto-accept policies are persisted via the SDK's `Storage` trait (same backend as protocol state). Key convention: `policy/{identity_did}/auto_accept`. Policies are device-local — cross-device sync is not supported (each device configures independently). Policies are never transmitted over the network. On SDK initialization, policies are loaded from storage and applied to the invitation evaluation pipeline.

### Invitation evaluation

When the SDK receives a context invitation, it evaluates in this order:

1. **Template check.** If the invitation includes a template ID, validate that the context params match the template exactly. Reject if params don't match (prevents template spoofing — claiming `bilateral-ephemeral` but including tool capabilities).
2. **Auto-accept check.** If a matching policy exists, evaluate trust requirement, TTL cap, and rate limit. If all pass, join automatically.
3. **Agent prompt.** If no auto-accept policy matches, surface the invitation to the agent/human for decision. The invitation includes full context metadata (§5.7) plus the template ID if present.

### Standing contexts (contact graph)

Standing bilateral contexts serve as the real-time communication primitive (spec §5.12.4). The SDK manages them as persistent infrastructure — the agent's contact list.

```
// Rust — get or create a standing context with a peer
let channel = sdk.standing_context(&bob_did).await?;
// Returns existing bilateral-persistent context if one exists,
// creates one if not. Idempotent.

// NOTE: this caller is the INITIATOR, so this send succeeds. It is the
// *peer's* send that fails-closed: a side that obtained its replica via
// Welcome-join (the common non-initiating peer, or a collision-losing
// did_hi) cannot send until the Phase-2E spawn-from-Welcome entrypoint
// lands (spec §5.15.8). The initiator side here is unaffected.
channel.send("Are you available for the 3pm sync?").await?;

// Python
channel = await sdk.standing_context(bob_did)
# initiator-side send (succeeds); the *peer's* Welcome-joined send
# fails-closed until Phase-2E (spec §5.15.8)
await channel.send("Are you available for the 3pm sync?")

// Swift
let channel = try await sdk.standingContext(with: bobDID)
// initiator-side send (succeeds); the *peer's* Welcome-joined send
// fails-closed until Phase-2E (spec §5.15.8)
try await channel.send("Are you available for the 3pm sync?")

// TypeScript — NOTE: the return shape MUST NOT add a `created: bool` /
// `peer_joined` discriminant; it is identical to every other binding.
const channel = await sdk.standingContext(bobDid);
// initiator-side send (succeeds); the *peer's* Welcome-joined send
// fails-closed until Phase-2E (spec §5.15.8)
await channel.send("Are you available for the 3pm sync?");

// Kotlin
val channel = sdk.standingContext(bobDid)
// initiator-side send (succeeds); the *peer's* Welcome-joined send
// fails-closed until Phase-2E (spec §5.15.8)
channel.send("Are you available for the 3pm sync?")
```

**Semantics of `standing_context`** (see spec §5.15.8 for the normative contract):

1. Check local state for an existing `bilateral-persistent` context with this peer DID.
2. If found and `Active`, return it. Zero network cost — instant.
3. If not found, create one (`bilateral-persistent` template), dispatch the Welcome, return the handle. First message queues until the peer joins.
4. If a prior handle was reaped or never joined, it is transparently **auto-revived** under the deterministic `derived_context_id` (spec §5.15.8, ADR-049 §10) — *not* a fresh create. A dangling/reaped handle never surfaces an error.

**`Ok` does not mean "peer joined."** A successful `standing_context` return means the **initiator's replica is created and the Welcome dispatched** — it does *not* block on the peer joining and does *not* confirm a bidirectional channel. An offline, slow, blocking, or consent-declining peer **all yield the identical `Ok`** (no synchronous join confirmation; the peer's join is observed only out-of-band). This uniformity is intentional: it is what forecloses a synchronous block/pair-existence oracle.

**Welcome-joiner caveat (decrypt-but-not-send until Phase 2E).** A caller whose replica was obtained via **Welcome-join** — the common non-initiating peer, and a collision-losing `did_hi` — can join and **decrypt** but **cannot send** in the standing context until the Phase-2E spawn-from-Welcome entrypoint lands (ADR-049 §Follow-ups #1, spec §5.15.8). Do **not** assume `standing_context(peer)` immediately yields a send-capable channel on the joiner side; the initiator side is unaffected.

**No create-vs-found discriminant (MUST).** FFI/SDK bindings **MUST NOT** enrich the `standing_context` return with a create-vs-found or `peer_joined` discriminant (e.g. a `created: bool`) — such a field re-opens the existence oracle the uniform `Ok` forecloses. The return shape MUST be identical across all bindings (every SDK language).

**Startup reconnection.** On SDK initialization, reconnect transport for all standing contexts. This is background work — the SDK reconnects to relays for all active persistent contexts and begins receiving queued messages. Standing contexts are available immediately after `sdk.init()` returns.

## CI Matrix

SDK CI follows the same three-tier structure as the Rust core. See `specs/16-test-infrastructure.md` §16.15 for the full tier definitions. Each language-specific standards file inherits these tiers and may add language-specific jobs.

### Tier 1 — PR Checks

Every push to a PR branch. Target: < 3 minutes. Must pass before review.

| Check | All SDKs |
|-------|----------|
| Lint | Language-specific linter (see per-language standards) |
| Format | Language-specific formatter (see per-language standards) |
| Type check | Static type analysis where available |
| Unit tests | Language test framework |
| Security scan | Dependency audit and vulnerability scanning (cargo-deny, pip-audit, npm audit, etc.) |
| Build | Release build for all target platforms |
| Docs | Documentation generation (verify no broken links) |

### Tier 2 — Merge Gate

Merge queue entry or push to `main`. Target: < 10 minutes. Required to merge.

| Check | All SDKs |
|-------|----------|
| All Tier 1 checks | (same as above) |
| Conformance tests | Cross-language JSON fixtures (wrapping key lifecycle, reorder buffer, error hierarchy, etc.) |
| Binding integration tests | End-to-end through FFI bridge: identity creation → context join → message roundtrip |

Conformance tests exercise cross-language fixtures that validate protocol behavior across SDK boundaries. They are more thorough than unit tests and require the Rust core to be built, so they run at the merge gate rather than on every push.

### Tier 3 — Nightly / Pre-Release

Scheduled (nightly) or manual trigger. Uncapped duration. Failures create issues but do not block merges.

| Check | All SDKs |
|-------|----------|
| All Tier 2 checks | (same as above) |
| Extended conformance | Full fixture suite with edge cases and adversarial inputs |
| Multi-platform matrix | All target platforms × all supported language versions |

No SDK release without 100% conformance pass (see `.docs/scaffold/shared.md`).

## Conformance Test Descriptions

The CI matrix above references cross-language JSON fixtures. See `.docs/scaffold/shared.md` for the full conformance test category table and fixture format. The subsections below describe specific test suites that require detailed behavioral verification beyond what the category table captures.

### Wrapping key lifecycle tests

Wrapping keys enable offline sender key distribution. Each member maintains a stable HPKE keypair per context, published as a LeafNode extension, used by other members to encrypt sender key material for offline recipients.

| Test ID | Verifies |
|---------|----------|
| `sender-keys-wrapping-stable-001` | Each member maintains a stable wrapping keypair per context, published as the `scp_wrapping_key` LeafNode extension |
| `sender-keys-wrapping-no-epoch-rotate-002` | Wrapping key does NOT rotate on MLS epoch advances — only on explicit identity key rotation |
| `sender-keys-wrapping-hpke-distribute-003` | Sender key distributions are HPKE-encrypted to each recipient's wrapping key |
| `sender-keys-wrapping-offline-unwrap-004` | Offline or late-joining members can unwrap sender key distributions using their wrapping key after reconnecting |

### Reorder buffer tests

The reorder buffer ensures reliable delivery without rejecting out-of-order messages. All authenticated messages are accepted; the buffer reorders before surfacing to the application, with bounded resource usage and gap alerting.

| Test ID | Verifies |
|---------|----------|
| `messaging-reorder-accept-all-001` | All authenticated messages are accepted regardless of sequence order |
| `messaging-reorder-before-delivery-002` | Reorder-before-delivery semantics: messages are held and reordered before surfacing to the application |
| `messaging-reorder-gap-timeout-003` | 30-second gap timeout with suppression alert — missing messages are marked as gaps and buffered messages are delivered |
| `messaging-reorder-buffer-bound-004` | 100-message buffer bound — when exceeded, buffer flushes in order with gap markers for missing sequence numbers |
| `messaging-reorder-gap-alert-005` | Gap detection triggers an alert to the application, not message rejection |

### Receive stream buffer tests

The receive stream buffers events for the application layer. When the consumer falls behind, the buffer drops the oldest events and emits a warning rather than blocking the transport layer.

| Test ID | Verifies |
|---------|----------|
| `receive-buffer-capacity-001` | Receive stream buffers up to 1,000 events (default) before dropping |
| `receive-buffer-overflow-drop-002` | When buffer is full, oldest unconsumed event is dropped (not newest) |
| `receive-buffer-overflow-warning-003` | `BufferOverflow` warning event is emitted when events are dropped, including dropped count |
| `receive-buffer-configurable-004` | Buffer size is configurable within bounds (min 100, max 10,000) |

## FFI Async Bridging Risks

Cross-language async bridging introduces subtle failure modes. All SDK binding implementations must account for these risks.

### 1. Tokio runtime must never block on Python GIL acquisition

PyO3 bridge functions use `py.allow_threads(|| rt.block_on(...))` which releases the GIL before entering the tokio runtime. If a tokio task attempts to acquire the Python GIL (e.g., via `Python::with_gil()`) while another thread holds the GIL and is blocked waiting for a tokio future, deadlock occurs. **Rule:** Rust-side tokio tasks must never call into Python synchronously. `Python::with_gil()` is only safe from non-async contexts where no GIL contention exists.

### 2. UniFFI callbacks execute on Rust threads

UniFFI-generated callback interfaces invoke the foreign callback on whatever Rust thread is running. Swift and Kotlin code must not assume callbacks arrive on the main thread or any specific dispatcher. **Rule:** UniFFI callbacks that touch UI or main-thread-only APIs must dispatch to the appropriate context (Swift: `MainActor.run {}`, Kotlin: `Dispatchers.Main`).

### 3. cbindgen runtime initialization is not reentrant

The shared tokio `Runtime` created at FFI initialization (`scp_init()`) must be called exactly once. A second call from Go/C#/Java will panic or return an error. **Rule:** Guard initialization with a `Once` / `OnceCell`. Document in all cbindgen-based SDK READMEs that `init()` is not reentrant.

### 4. Shutdown ordering: language cleanup before Rust runtime drop

If the Rust tokio runtime is dropped while language-side objects still hold FFI handles, those objects will attempt to call into a dead runtime. **Rule:** SDKs must ensure all SCP objects are disposed/closed before the FFI runtime is shut down. Implement a shutdown hook or reference counter that blocks runtime drop until all outstanding handles are released (with a configurable timeout, default 5 seconds).
