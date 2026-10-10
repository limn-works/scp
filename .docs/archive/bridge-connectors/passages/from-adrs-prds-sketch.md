# Passages removed from ADRs, PRDs and the sketch

> **ARCHIVED — NOT LIVE TEXT.** This file records every line that the Track BR slice S1 pull request removed or changed in a live ADR, PRD or `.docs/sketch.md` on 2026-10-09. Nothing below states current protocol, a current decision or a current story. Read `../HISTORY.md` for the history and state of each artifact before reviving any passage.

Each section names the source file, the heading or PRD entry that enclosed the passage, and the passage's line range in that file on main when S1 archived it. A four-backtick `text` fence holds the original lines byte for byte, so embedded fences, headings and JSON keep their exact text. When S1 changed a line instead of deleting it, a second fence after "Live text after the cut:" holds the replacement. To restore a passage, put the fenced lines back at the named location and delete the replacement lines.

Two kinds of removed text live elsewhere in this archive:

- ADR-023, Bridge Connector Protocol, sits whole in `../adrs/ADR-023-bridge-connector-protocol.md`.
- The SCP-BCH PRD, `bridge-cooperative.json`, sits byte-identical in `../prds/bridge-cooperative.json`.

## `.docs/adrs/phase-2.md`, under `### Decision`, line 1955 on main when archived

````text
The relay's `/scp/v1` route is served on the node's existing TLS-terminated **Full** public surface for EXTERNAL participants — not a separate listener mode or gated surface — while the node's dev/control and bridge endpoints remain loopback-only. Opening the relay to external participants does NOT open dev/bridge endpoints.
````

Live text after the cut:

````text
The relay's `/scp/v1` route is served on the node's existing TLS-terminated **Full** public surface for EXTERNAL participants — not a separate listener mode or gated surface — while the node's dev/control endpoints remain loopback-only. Opening the relay to external participants does NOT open dev/control endpoints.
````

## `.docs/adrs/phase-3.md`, under `### Acceptance Criteria`, lines 334–336 on main when archived

These lines labelled the Swift SDK receive decision "ADR-023". That decision is ADR-026, Swift SDK, in `phase-5.md`. The TypeScript and Kotlin labels in the same sentence named ADR-019, Data Provenance, and ADR-027, Android Platform Adapter; the decisions they cite are ADR-022, TypeScript SDK, and ADR-028, Kotlin SDK. The S1 pull request corrected all three labels because ADR-023 left the live documents.

````text
   This matches the detail level of the TypeScript (ADR-019: `onMessage`/`onError`/`onComplete`
   callbacks → async generator), Swift (ADR-023: `AsyncStream<Message>` with
   `continuation.yield`/`finish`), and Kotlin (ADR-027: `callbackFlow`/`awaitClose`) receive
````

Live text after the cut:

````text
   This matches the detail level of the TypeScript (ADR-022: `onMessage`/`onError`/`onComplete`
   callbacks → async generator), Swift (ADR-026: `AsyncStream<Message>` with
   `continuation.yield`/`finish`), and Kotlin (ADR-028: `callbackFlow`/`awaitClose`) receive
````

## `.docs/adrs/phase-4.md`, under `### Decision`, line 1609 on main when archived

````text
Protocol-level feature flags for node roles. Not challenge-testable — these describe what a node does, not what an agent can prove. Initial set: `mls-group-management`, `key-rotation`, `governance-participation`, `relay-operation`, `bridge-operation`.
````

Live text after the cut:

````text
Protocol-level feature flags for node roles. Not challenge-testable — these describe what a node does, not what an agent can prove. Initial set: `mls-group-management`, `key-rotation`, `governance-participation`, `relay-operation`.
````

## `.docs/adrs/phase-4.md`, under `### Acceptance Criteria`, line 1654 on main when archived

````text
2. **Protocol registry** contains all 28 challenge capability URIs and 5 system capability URIs. Lookup by URI returns registry metadata (category, description, parameter schema). Unknown `scp:capability:*` URIs return `Err(UnknownProtocolCapability)`.
````

Live text after the cut:

````text
2. **Protocol registry** contains all 28 challenge capability URIs and 4 system capability URIs. Lookup by URI returns registry metadata (category, description, parameter schema). Unknown `scp:capability:*` URIs return `Err(UnknownProtocolCapability)`.
````

## `.docs/adrs/phase-5.md`, under `# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK`, line 1 on main when archived

````text
# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK
````

Live text after the cut:

````text
# Phase 5 Architecture Decision Records — Media, Apple Platform, Swift SDK
````

## `.docs/adrs/phase-5.md`, under `# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK`, line 4 on main when archived

````text
**Phase goal:** Platform bridge infrastructure, real-time media transport, Apple platform, Swift SDK.
````

Live text after the cut:

````text
**Phase goal:** Real-time media transport, Apple platform, Swift SDK.
````

## `.docs/adrs/phase-5.md`, under `# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK`, line 11 on main when archived

````text
       ├── ADR-023 (Bridges) <── ADR-019 (Provenance), ADR-008 (Governance)
````

The cut deleted these lines and left no replacement text.

## `.docs/adrs/phase-5.md`, under `# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK`, line 17 on main when archived

````text
Build order: ADR-023 + ADR-024 (parallel, both depend on Phase 1-4) --> ADR-025 (depends on Phase 1-2 Rust + ADR-021) --> ADR-026 (depends on ADR-021 + ADR-025)
````

Live text after the cut:

````text
Build order: ADR-024 (depends on Phase 1-4) --> ADR-025 (depends on Phase 1-2 Rust + ADR-021) --> ADR-026 (depends on ADR-021 + ADR-025)
````

## `.docs/adrs/phase-5.md`, lines 18–192 on main when archived

Lines 18–20 held a blank line, the `---` separator and a blank line. Lines 21–192 held ADR-023, Bridge Connector Protocol, from its heading through its estimate line. The diff counts the separator that followed ADR-023 as the surviving copy, so the live file still separates its header from ADR-024. ADR-023 sits verbatim in `../adrs/ADR-023-bridge-connector-protocol.md`, which also carries this file's header lines 1–19 as they stood on main.

## `.docs/adrs/phase-6.md`, under `### Rationale`, line 3648 on main when archived

````text
The self-attestation model is acceptable for identity links specifically because issuer == subject. The identity's controller is the only party with incentive to create the attestation, and the only party who can perform the OAuth flow. Falsifying a link provides no protocol benefit: shadow claiming (§3.5.5) verifies the external identity independently, and social graph import only surfaces contacts who genuinely control both identities.
````

Live text after the cut:

````text
The self-attestation model is acceptable for identity links specifically because issuer == subject. The identity's controller is the only party with incentive to create the attestation, and the only party who can perform the OAuth flow. Falsifying a link provides no protocol benefit: social graph import only surfaces contacts who genuinely control both identities.
````

## `.docs/adrs/phase-6.md`, under `### Security Analysis`, line 3660 on main when archived

````text
**Self-attestation attack surface.** A malicious user could create a Class 1 attestation claiming to have performed OAuth verification without actually doing so. The attestation would have a valid signature. Defense: (a) the claim is "I control external account X" — the only use cases (shadow claiming, social graph import) independently verify the external identity, so a false claim has no effect; (b) the `subject_id` in the proof is meaningless without the external platform recognizing it, limiting social engineering; (c) stale attestations (past renewal interval) are degraded, forcing periodic re-verification.
````

Live text after the cut:

````text
**Self-attestation attack surface.** A malicious user could create a Class 1 attestation claiming to have performed OAuth verification without actually doing so. The attestation would have a valid signature. Defense: (a) the claim is "I control external account X" — the only use case (social graph import) independently verifies the external identity, so a false claim has no effect; (b) the `subject_id` in the proof is meaningless without the external platform recognizing it, limiting social engineering; (c) stale attestations (past renewal interval) are degraded, forcing periodic re-verification.
````

## `.docs/adrs/ADR-048-scp-multi-instance.md`, under `### 1. `SCP` is the first-class SDK-level opaque object in all four language SDKs`, line 54 on main when archived

````text
The class is named after the protocol, not after internal plumbing. This matches the prevailing SDK convention (`OpenAI()`, `Anthropic()`, `Stripe()`) and avoids the collisions that `Node`, `Bridge`, or `Client` would create with existing application-layer classes (`server.py:125`, `server.ts:223`, `BridgeConnector` in spec §12).
````

Live text after the cut:

````text
The class is named after the protocol, not after internal plumbing. This matches the prevailing SDK convention (`OpenAI()`, `Anthropic()`, `Stripe()`) and avoids the collisions that `Node`, `Bridge`, or `Client` would create with existing application-layer classes (`server.py:125`, `server.ts:223`).
````

## `.docs/adrs/ADR-048-scp-multi-instance.md`, under `### 2. `BridgeInstance` splits into three per-bridge concrete structs behind a shared trait`, line 60 on main when archived

````text
- `PyBridgeInstance`, `NapiBridgeInstance`, `UniffiBridgeInstance` — concrete per-bridge structs holding typed fields for all bridge-specific registries (FFI_BRIDGE_STATE, MCP server/client registries, CREDENTIAL_STORE, identity_custody_registry, identity_link_attestation_registry, context_handle_registry, etc.).
````

Live text after the cut:

````text
- `PyBridgeInstance`, `NapiBridgeInstance`, `UniffiBridgeInstance` — concrete per-bridge structs holding typed fields for all bridge-specific registries (FFI_BRIDGE_STATE, MCP server/client registries, identity_custody_registry, identity_link_attestation_registry, context_handle_registry, etc.).
````

## `.docs/adrs/ADR-049-actor-per-context.md`, under `### 10. Actor panic recovery`, line 265 on main when archived

````text
**Recovery-surface honesty (mirrors §12a's webhook-deferral disclosure).** `SupervisorHandle::clear_poison` is a Rust-core recovery primitive that is **not yet wired to an FFI/operator-facing surface** — no bridge exports it and no SDK wrapper calls it. The complete, tested end-to-end recovery path available to a deployed node today is therefore a **process restart** (which re-runs `restore_all_contexts` and drops the in-memory poison record). `clear_poison` is exercised by Rust-core tests and is ready for an operator surface to call, but until that surface lands, "operator-driven recovery" in production means restart. This asymmetry is recorded here in the system of record rather than only in code comments, exactly as the §12a webhook-target deferral is.
````

Live text after the cut:

````text
**Recovery-surface honesty.** `SupervisorHandle::clear_poison` is a Rust-core recovery primitive that is **not yet wired to an FFI/operator-facing surface** — no bridge exports it and no SDK wrapper calls it. The complete, tested end-to-end recovery path available to a deployed node today is therefore a **process restart** (which re-runs `restore_all_contexts` and drops the in-memory poison record). `clear_poison` is exercised by Rust-core tests and is ready for an operator surface to call, but until that surface lands, "operator-driven recovery" in production means restart. This asymmetry is recorded here in the system of record rather than only in code comments.
````

## `.docs/adrs/ADR-049-actor-per-context.md`, under `### 10. Actor panic recovery`, line 284 on main when archived

````text
**Crash/poison consumer-surfacing boundary (mirrors the §12a webhook-deferral note).** Poison and crash are surfaced to FFI/SDK consumers **via a typed error code on the next per-context operation**, NOT through the cheap cached per-handle state getter. Concretely:
````

Live text after the cut:

````text
**Crash/poison consumer-surfacing boundary.** Poison and crash are surfaced to FFI/SDK consumers **via a typed error code on the next per-context operation**, NOT through the cheap cached per-handle state getter. Concretely:
````

## `.docs/adrs/ADR-049-actor-per-context.md`, under `### 10. Actor panic recovery`, line 290 on main when archived

````text
This boundary is the same shape as §12a's webhook-target deferral: the durable, tested signal path (error codes on operations) is complete; the cheap cached getter is intentionally not promoted to a live read, and that asymmetry is recorded here in the system of record rather than only in code comments.
````

Live text after the cut:

````text
The durable, tested signal path (error codes on operations) is complete; the cheap cached getter is intentionally not promoted to a live read, and that asymmetry is recorded here in the system of record rather than only in code comments.
````

## `.docs/adrs/ADR-049-actor-per-context.md`, under `### 12. Lock-free read invariant`, line 322 on main when archived

````text
- Test-only mock/store locks in `#[cfg(test)]` modules — the mock OAuth provider (`bridge/oauth.rs`), the `InMemoryCredentialStore` (`economy/credentials.rs`), and the governance-engine share in the timeout-callback tests (`context/governance/timeout.rs`). Not runtime read paths.
````

Live text after the cut:

````text
- Test-only mock/store locks in `#[cfg(test)]` modules — the `InMemoryCredentialStore` (`economy/credentials.rs`), and the governance-engine share in the timeout-callback tests (`context/governance/timeout.rs`). Not runtime read paths.
````

## `.docs/adrs/ADR-049-actor-per-context.md`, under `### 12a. Event-channel observer surface`, line 328 on main when archived

````text
The `Supervisor` owns a `broadcast::Sender<(String, ContextEvent)>` in a `OnceLock` (`event_tx`). `Supervisor::subscribe_events()` is the public, read-only observer surface: it returns `Some(broadcast::Receiver)` when the channel is enabled, `None` otherwise. The per-context actors emit `(context_id, ContextEvent)` onto this sender via `emit_event_into` (payloads stripped of plaintext first — see `strip_event_payload`); the FFI node-startup path subscribes once and drives the outbound webhook dispatcher (spec §12.10.5).
````

Live text after the cut:

````text
The `Supervisor` owns a `broadcast::Sender<(String, ContextEvent)>` in a `OnceLock` (`event_tx`). `Supervisor::subscribe_events()` is the public, read-only observer surface: it returns `Some(broadcast::Receiver)` when the channel is enabled, `None` otherwise. The per-context actors emit `(context_id, ContextEvent)` onto this sender via `emit_event_into` (payloads stripped of plaintext first — see `strip_event_payload`).
````

## `.docs/adrs/ADR-049-actor-per-context.md`, under `### 12a. Event-channel observer surface`, lines 332–334 on main when archived

````text
Production supervisors enable the channel **unconditionally** — each FFI bridge's `build_supervisor` passes `Some(event_tx)`, so `subscribe_events()` always yields a receiver in production. Query/test shims (e.g. `Supervisor::for_query_shim`) may construct a supervisor with no channel; for those `subscribe_events()` returns `None` and observers skip wiring rather than panic. The asymmetry is intentional: the channel exists to feed external sinks (webhooks, SDK listeners), which only matter when a node is actually running.

**Scope of the current wiring.** The subscribe → map → dispatch path is wired end-to-end: a `ContextEvent` emitted by a context actor reaches the `WebhookDispatcher`. What is **not** yet wired in production is the dispatcher's *outbound target registration* — there is no operator-facing surface that registers webhook URLs/signing keys onto the dispatcher's target table. The dispatcher therefore holds zero targets at runtime, and `dispatch_event` is a no-op fan-out until such a surface exists; delivery is end-to-end only once an operator-facing target-registration API drives `WebhookDispatcher::register`. The event *plumbing* is complete and tested; actual outbound delivery is gated on that future operator-config surface. Until it lands, the only consumers exercising the full path are the integration tests, which register targets directly (see `scp-node/tests/webhook_event_wiring.rs`).
````

Live text after the cut:

````text
Production supervisors enable the channel **unconditionally** — each FFI bridge's `build_supervisor` passes `Some(event_tx)`, so `subscribe_events()` always yields a receiver in production. Query/test shims (e.g. `Supervisor::for_query_shim`) may construct a supervisor with no channel; for those `subscribe_events()` returns `None` and observers skip wiring rather than panic. The asymmetry is intentional: the channel exists to feed external sinks, which only matter when a node is actually running.
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `# ADR-062: Capability Injection — Real Backends and Test-Harness-Only Nullifiers`, line 3 on main when archived

````text
**Status:** Accepted — the *decision* is dated 2026-07-14; implementation is a separate, forward program staged across the slices below (see *Rollout — ordered slices*). Accepted records that the design is settled, not that it is realized. Merged work executes part of it: the in-memory DHT, credential-store, blob-storage, and relay-publisher default selections are severed, the `scp-platform` nullifier doubles are defined behind `#[cfg(feature = "testing")]`, and production pre-rotation custody fails closed with the typed `SCP-IDENT-1059` on all three FFI bridges. **§Decision 6's prove-absence property now holds for storage confidentiality.** Four shipped FFI manifests once enabled `allow_unencrypted_storage` on their `scp-node` dependency, and `scripts/check-shipped-feature-graph.sh` once allowlisted that feature three times (`scp-core/`, `scp-node/`, `scp-runtime/`) — a confidentiality nullifier, because it unseals an `EncryptedStorage` bound through `ProtocolRepository::new_for_testing`, rather than a member of a durability-only or real-backend class §Decision 6 restricts its allowlist to. Both node front doors in `scp_ffi_common::server` now reach a production `Node::start`: `start_node_in_memory` wraps its ephemeral `InMemoryStorage` in an `EncryptingAdapter`, and `start_node_local` takes an already-encrypted handle from whichever backend its bridge instance selected. Those four dependency edges and those three allowlist rows are gone, and that gate's `NULLIFIER_CONTROL_FEATURES` list now names all three rows, so its `assert_allowlist_has_no_nullifier` fixture rejects an edit that restores any of them. A second path carried those same features past every per-artifact check: resolver 2 unifies normal-dependency features per invocation, `crates/scp-testing` carries `testing` and `allow_unencrypted_storage` on normal edges, and a workspace-wide `cargo build` therefore compiled each nullifier into every FFI bridge cdylib that `.github/workflows/build-matrix.yml` uploads and `.github/workflows/release.yml` Authenticode-signs. Root `Cargo.toml` now omits `crates/scp-testing` from `default-members`, that workflow builds each uploaded binary one package per invocation into a directory no test step rewrites, and G1 resolves a bare `cargo build` as a sixth artifact so neither guard can lapse unnoticed. **Execution of this ADR is still not complete:** a **real** pre-rotation custody backend remains forward work, which this ADR does not build and holds out of scope (RFC #2130 / #1729 / #1777).
````

Live text after the cut:

````text
**Status:** Accepted — the *decision* is dated 2026-07-14; implementation is a separate, forward program staged across the slices below (see *Rollout — ordered slices*). Accepted records that the design is settled, not that it is realized. Merged work executes part of it: the in-memory DHT, blob-storage, and relay-publisher default selections are severed, the `scp-platform` nullifier doubles are defined behind `#[cfg(feature = "testing")]`, and production pre-rotation custody fails closed with the typed `SCP-IDENT-1059` on all three FFI bridges. **§Decision 6's prove-absence property now holds for storage confidentiality.** Four shipped FFI manifests once enabled `allow_unencrypted_storage` on their `scp-node` dependency, and `scripts/check-shipped-feature-graph.sh` once allowlisted that feature three times (`scp-core/`, `scp-node/`, `scp-runtime/`) — a confidentiality nullifier, because it unseals an `EncryptedStorage` bound through `ProtocolRepository::new_for_testing`, rather than a member of a durability-only or real-backend class §Decision 6 restricts its allowlist to. Both node front doors in `scp_ffi_common::server` now reach a production `Node::start`: `start_node_in_memory` wraps its ephemeral `InMemoryStorage` in an `EncryptingAdapter`, and `start_node_local` takes an already-encrypted handle from whichever backend its bridge instance selected. Those four dependency edges and those three allowlist rows are gone, and that gate's `NULLIFIER_CONTROL_FEATURES` list now names all three rows, so its `assert_allowlist_has_no_nullifier` fixture rejects an edit that restores any of them. A second path carried those same features past every per-artifact check: resolver 2 unifies normal-dependency features per invocation, `crates/scp-testing` carries `testing` and `allow_unencrypted_storage` on normal edges, and a workspace-wide `cargo build` therefore compiled each nullifier into every FFI bridge cdylib that `.github/workflows/build-matrix.yml` uploads and `.github/workflows/release.yml` Authenticode-signs. Root `Cargo.toml` now omits `crates/scp-testing` from `default-members`, that workflow builds each uploaded binary one package per invocation into a directory no test step rewrites, and G1 resolves a bare `cargo build` as a sixth artifact so neither guard can lapse unnoticed. **Execution of this ADR is still not complete:** a **real** pre-rotation custody backend remains forward work, which this ADR does not build and holds out of scope (RFC #2130 / #1729 / #1777).
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `# ADR-062: Capability Injection — Real Backends and Test-Harness-Only Nullifiers`, line 7 on main when archived

````text
**Motivating defects:** #627 (CLOSED, unmet — `production-dht` never enabled for PyO3/NAPI), #1518 (`ConcreteDidMethod` locks the shared FFI layer to `InMemoryDhtClient`), #1880 (rotation/migration publish through a fresh non-shared client that never reaches/invalidates the resolver). **#1733 (eliminate `scp_platform::testing` imports from production paths + CI enforcement) is FOLDED** for the capabilities this ADR fixes (custody/attestation/DHT/storage) and closed-as-folded at Slice 6 (§Folding #1733); its `InMemoryPreRotationCustody` row is carried to RFC #2130 (pre-rotation out of scope). **Pre-rotation custody (E5) is OUT OF SCOPE** — its realization is a proposal in RFC #2130 (#1729 / #1777); this ADR fixes only capabilities that have a real backend today (custody → File/Sqlite/callback; storage → Sqlite/filesystem; credentials → a durable store; attestation → declined per spec §9:187).
````

Live text after the cut:

````text
**Motivating defects:** #627 (CLOSED, unmet — `production-dht` never enabled for PyO3/NAPI), #1518 (`ConcreteDidMethod` locks the shared FFI layer to `InMemoryDhtClient`), #1880 (rotation/migration publish through a fresh non-shared client that never reaches/invalidates the resolver). **#1733 (eliminate `scp_platform::testing` imports from production paths + CI enforcement) is FOLDED** for the capabilities this ADR fixes (custody/attestation/DHT/storage) and closed-as-folded at Slice 6 (§Folding #1733); its `InMemoryPreRotationCustody` row is carried to RFC #2130 (pre-rotation out of scope). **Pre-rotation custody (E5) is OUT OF SCOPE** — its realization is a proposal in RFC #2130 (#1729 / #1777); this ADR fixes only capabilities that have a real backend today (custody → File/Sqlite/callback; storage → Sqlite/filesystem; attestation → declined per spec §9:187).
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Context`, line 16 on main when archived

````text
- **E2 (HIGH) — credentials.** `InMemoryCredentialStore` ("Not suitable for production," `credentials.rs:502-506`, `impl Default :556`) wired on shipped NAPI+PyO3 as a **hardcoded concrete type** (`napi/runtime.rs:313`). The `impl Default` is a **LIVE SCP-CAPSEL-8000/8011 violation** (a default selection) shipping now — see §Decision 5.
````

The cut deleted these lines and left no replacement text.

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Context`, line 18 on main when archived

````text
- **E4 (MED) — relay-publisher default-selection hygiene (WRITE-path only).** The ADR-062 (dev-backend-cleanup) concern at the relay layer is a single by-construction default-selection: `RepublishManager` **defaults its publisher type parameter to the test double** — `RepublishManager<D, R = InMemoryRelayPublisher>` (`republish.rs:397`); the only impls of the `RelayPublisher` trait are `InMemoryRelayPublisher` + test doubles. That in-memory *default* is a **latent, by-construction default-selection** violation of exactly the E1 (`DidDht<D = InMemoryDhtClient>` default) class — the instant a production `RepublishManager` is wired it would bind the in-memory dev publisher unless severed by construction. Today the relay layer receives no identity records because relay-republish is **entirely unwired in production** (no shipped `RepublishManager` construction; `::new` sets `relay_publisher: None`, and the only constructions are `#[cfg(test)]`, `republish.rs:863-917`), **not** because the default swallows publishes. On the READ side, `NoOpRelayQuerier` (`resolver.rs:309`) ships honestly and unchanged (it fails CLOSED, not a nullifier — see §Decision 5). **Building relay resolution itself — the real `MultiRelayQuerier`, the real `RelayPublisher`, the identity-record frame, relay-side validation, and the fix for the republish loop dropping signature/sequence (`republish.rs:703`) — is issue #482 (a feature; spec §3.10.2/§3.10.4/§3.10.8, §9.10.12), explicitly OUT of ADR-062 scope.** ADR-062's only E4 item is severing the `InMemoryRelayPublisher` default (below), matching E1/E2/E3.
````

Live text after the cut:

````text
- **E4 (MED) — relay-publisher default-selection hygiene (WRITE-path only).** The ADR-062 (dev-backend-cleanup) concern at the relay layer is a single by-construction default-selection: `RepublishManager` **defaults its publisher type parameter to the test double** — `RepublishManager<D, R = InMemoryRelayPublisher>` (`republish.rs:397`); the only impls of the `RelayPublisher` trait are `InMemoryRelayPublisher` + test doubles. That in-memory *default* is a **latent, by-construction default-selection** violation of exactly the E1 (`DidDht<D = InMemoryDhtClient>` default) class — the instant a production `RepublishManager` is wired it would bind the in-memory dev publisher unless severed by construction. Today the relay layer receives no identity records because relay-republish is **entirely unwired in production** (no shipped `RepublishManager` construction; `::new` sets `relay_publisher: None`, and the only constructions are `#[cfg(test)]`, `republish.rs:863-917`), **not** because the default swallows publishes. On the READ side, `NoOpRelayQuerier` (`resolver.rs:309`) ships honestly and unchanged (it fails CLOSED, not a nullifier — see §Decision 5). **Building relay resolution itself — the real `MultiRelayQuerier`, the real `RelayPublisher`, the identity-record frame, relay-side validation, and the fix for the republish loop dropping signature/sequence (`republish.rs:703`) — is issue #482 (a feature; spec §3.10.2/§3.10.4/§3.10.8, §9.10.12), explicitly OUT of ADR-062 scope.** ADR-062's only E4 item is severing the `InMemoryRelayPublisher` default (below), matching E1/E3.
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Capability classification (§17.17.2 SCP-CAPSEL-8010 — mandatory before ship)`, line 41 on main when archived

````text
| Credential storage (E2) | `InMemoryCredentialStore` | **durability-only** (RAM-only tokens re-obtainable by re-auth) — but `impl Default` is a **LIVE SCP-CAPSEL-8000/8011 violation** | a durable credential store | Slice 9 |
````

The cut deleted these lines and left no replacement text.

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Capability classification (§17.17.2 SCP-CAPSEL-8010 — mandatory before ship)`, line 44 on main when archived

````text
| Relay layer WRITE (E4) | `InMemoryRelayPublisher` as the `RepublishManager<R = InMemoryRelayPublisher>` **default** (`republish.rs:397`) | **WRITE-path LATENT, by-construction default-selection** violation, structurally identical to E1's `DidDht<D = InMemoryDhtClient>` default: the instant a production `RepublishManager` is wired it would bind the in-memory dev publisher unless severed by construction. Today relays receive no identity records because relay-republish is **entirely unwired in production** (no shipped `RepublishManager` construction; `::new` sets `relay_publisher: None`; only `#[cfg(test)]` constructions exist), NOT because the default swallows publishes. Must be severed exactly as E1 was in Slice 1. | **ADR-062 item (Slice 11):** sever the `InMemoryRelayPublisher` default (require an explicit publisher) + demote to `#[cfg(any(test, feature="testing"))]`, matching E1/E2/E3. **Out of ADR-062 scope → #482:** building the real `RelayPublisher`, the identity-record frame (§9.10.12), and fixing the republish loop's signature/sequence drop (`republish.rs:703`). | Slice 11 (sever only) |
````

Live text after the cut:

````text
| Relay layer WRITE (E4) | `InMemoryRelayPublisher` as the `RepublishManager<R = InMemoryRelayPublisher>` **default** (`republish.rs:397`) | **WRITE-path LATENT, by-construction default-selection** violation, structurally identical to E1's `DidDht<D = InMemoryDhtClient>` default: the instant a production `RepublishManager` is wired it would bind the in-memory dev publisher unless severed by construction. Today relays receive no identity records because relay-republish is **entirely unwired in production** (no shipped `RepublishManager` construction; `::new` sets `relay_publisher: None`; only `#[cfg(test)]` constructions exist), NOT because the default swallows publishes. Must be severed exactly as E1 was in Slice 1. | **ADR-062 item (Slice 11):** sever the `InMemoryRelayPublisher` default (require an explicit publisher) + demote to `#[cfg(any(test, feature="testing"))]`, matching E1/E3. **Out of ADR-062 scope → #482:** building the real `RelayPublisher`, the identity-record frame (§9.10.12), and fixing the republish loop's signature/sequence drop (`republish.rs:703`). | Slice 11 (sever only) |
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## The split (execution units)`, line 51 on main when archived

````text
- **Unit 3 (live SCP-CAPSEL fixes + completeness): E2/E3/E4 (Slices 9–11).** Their selection-boundary fixes (delete `impl Default`) are live SCP-CAPSEL violations, storied now (§17.17.2 forbids leaving a capability unclassified/unfixed).
````

Live text after the cut:

````text
- **Unit 3 (live SCP-CAPSEL fixes + completeness): E3/E4 (Slices 10–11).** Their selection-boundary fixes (delete `impl Default`) are live SCP-CAPSEL violations, storied now (§17.17.2 forbids leaving a capability unclassified/unfixed).
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)`, line 90 on main when archived

````text
### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)
````

Live text after the cut:

````text
### 5. Blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)`, line 92 on main when archived

````text
These are **not** "later slices, not yet storied" (that would be the deferral this ADR forbids). Each is classified (table above) and gets a real story (Slices 9–11), authored now:
````

Live text after the cut:

````text
These are **not** "later slices, not yet storied" (that would be the deferral this ADR forbids). Each is classified (table above) and gets a real story (Slices 10–11), authored now:
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)`, line 94 on main when archived

````text
- **E2 credentials (Slice 9).** `BridgeCredentialStore` is RPITIT → an `enum FfiCredentialStore { Durable(..), #[cfg(feature = "testing")] InMemory }`; **delete `impl Default` (`credentials.rs:556`) — a LIVE SCP-CAPSEL-8000/8011 violation, not deferrable** — and require an explicit selection with a real durable backend. (Classified durability-only: RAM-only tokens are re-obtainable by re-auth; the selection-boundary fix is the security-relevant part.)
````

The cut deleted these lines and left no replacement text.

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)`, line 102 on main when archived

````text
  **WRITE arm — the one ADR-062 item: sever the default.** `RepublishManager` defaults `R = InMemoryRelayPublisher` (`republish.rs:397`) — a WRITE-path **latent, by-construction default-selection** violation structurally identical to E1's `DidDht<D = InMemoryDhtClient>` default: the instant a production `RepublishManager` is wired it would bind the in-memory dev publisher unless severed by construction. Today relays receive no identity records because relay-republish is **entirely unwired in production** (no shipped `RepublishManager` construction; `::new` sets `relay_publisher: None`; the only constructions are `#[cfg(test)]`, `republish.rs:863-917`), **not** because the default swallows publishes. ADR-062 **severs the default exactly as E1 was in Slice 1**: require an explicit publisher and demote `InMemoryRelayPublisher` to `#[cfg(any(test, feature="testing"))]`. That is the whole ADR-062 E4 deliverable — a selection-boundary hygiene fix, matching E2/E3.
````

Live text after the cut:

````text
  **WRITE arm — the one ADR-062 item: sever the default.** `RepublishManager` defaults `R = InMemoryRelayPublisher` (`republish.rs:397`) — a WRITE-path **latent, by-construction default-selection** violation structurally identical to E1's `DidDht<D = InMemoryDhtClient>` default: the instant a production `RepublishManager` is wired it would bind the in-memory dev publisher unless severed by construction. Today relays receive no identity records because relay-republish is **entirely unwired in production** (no shipped `RepublishManager` construction; `::new` sets `relay_publisher: None`; the only constructions are `#[cfg(test)]`, `republish.rs:863-917`), **not** because the default swallows publishes. ADR-062 **severs the default exactly as E1 was in Slice 1**: require an explicit publisher and demote `InMemoryRelayPublisher` to `#[cfg(any(test, feature="testing"))]`. That is the whole ADR-062 E4 deliverable — a selection-boundary hygiene fix, matching E3.
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `### Dispatch mechanism (per trait object-safety)`, line 111 on main when archived

````text
RPITIT traits — **not object-safe** — dispatch via a no-`Default` **enum** whose in-memory arm is `#[cfg(feature = "testing")]`: `scp_dht::DhtClient`, `KeyCustody`, `Storage`, `BridgeCredentialStore`. (`PreRotationCustody` is also RPITIT and would follow the same enum shape, but its realization is out of scope — RFC #2130.) Object-safe async-trait traits (`ContextPersistence`) → required non-`Option` `Arc<dyn Trait>`. ADR-049's ban is the lock-free-read hot path only; these are write/setup paths.
````

Live text after the cut:

````text
RPITIT traits — **not object-safe** — dispatch via a no-`Default` **enum** whose in-memory arm is `#[cfg(feature = "testing")]`: `scp_dht::DhtClient`, `KeyCustody`, `Storage`. (`PreRotationCustody` is also RPITIT and would follow the same enum shape, but its realization is out of scope — RFC #2130.) Object-safe async-trait traits (`ContextPersistence`) → required non-`Option` `Arc<dyn Trait>`. ADR-049's ban is the lock-free-read hot path only; these are write/setup paths.
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Consequences`, line 136 on main when archived

````text
- **No *classified-and-gated* nullifier is reachable in a shipped artifact** — not by default (the `DidDht` default type param is gone), fallback, or runtime config. This is precise about what each mechanism buys: G1 proves the *gated* nullifiers (behind `…/testing`) absent from the shipped feature graph; it does not, and cannot, prove that *every* capability has been classified — **classification-completeness is §17.17.2's mandate** (every capability's dev arm classified before it ships), enforced by the classification table above + review, not by G1. Together they close the loop: the table classifies all seven capabilities; the nullifiers among them are gated; G1 proves the gated ones absent. **E2 credentials, E3 blob, E4 relay-publisher default are classified + storied (Slices 9–11)** — E2/E3 in-memory arms (durability-only) ship until their slices land, but their live `impl Default` SCP-CAPSEL violations are the storied fixes, not hidden residue; E4's ADR-062 item is severing the `InMemoryRelayPublisher` default (Slice 11), while `NoOpRelayQuerier` is not a nullifier and ships honestly (building relay resolution is #482, out of scope; §Decision 5). G1 tightens per slice.
````

Live text after the cut:

````text
- **No *classified-and-gated* nullifier is reachable in a shipped artifact** — not by default (the `DidDht` default type param is gone), fallback, or runtime config. This is precise about what each mechanism buys: G1 proves the *gated* nullifiers (behind `…/testing`) absent from the shipped feature graph; it does not, and cannot, prove that *every* capability has been classified — **classification-completeness is §17.17.2's mandate** (every capability's dev arm classified before it ships), enforced by the classification table above + review, not by G1. Together they close the loop: the table classifies all seven capabilities; the nullifiers among them are gated; G1 proves the gated ones absent. **E3 blob and E4 relay-publisher default are classified + storied (Slices 10–11)** — the E3 in-memory arm (durability-only) ships until its slice lands, but its live `impl Default` SCP-CAPSEL violation is the storied fix, not hidden residue; E4's ADR-062 item is severing the `InMemoryRelayPublisher` default (Slice 11), while `NoOpRelayQuerier` is not a nullifier and ships honestly (building relay resolution is #482, out of scope; §Decision 5). G1 tightens per slice.
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Alternatives considered`, line 148 on main when archived

````text
- **`Arc<dyn>` for the RPITIT seams — rejected** (not object-safe; the enum shape is used for `DhtClient`/`KeyCustody`/`Storage`/`BridgeCredentialStore`).
````

Live text after the cut:

````text
- **`Arc<dyn>` for the RPITIT seams — rejected** (not object-safe; the enum shape is used for `DhtClient`/`KeyCustody`/`Storage`).
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Alternatives considered`, line 151 on main when archived

````text
- **E2/E3/E4 "scheduled but not storied" — REJECTED** (deferral dressed as a decision; §17.17.2 forbids an unclassified/unfixed shipped capability; E2/E3 `impl Default` are live violations).
````

Live text after the cut:

````text
- **E3/E4 "scheduled but not storied" — REJECTED** (deferral dressed as a decision; §17.17.2 forbids an unclassified/unfixed shipped capability; the E3 `impl Default` is a live violation).
````

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Rollout — ordered slices`, line 166 on main when archived

````text
9. **Slice 9 — E2 credentials (SCP-CAPINJECT-009).** `FfiCredentialStore` enum seam + durable backend + **delete `impl Default` (live fix)**; InMemory → test-harness-only.
````

The cut deleted these lines and left no replacement text.

## `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`, under `## Provenance chain`, line 182 on main when archived

````text
§17.17 (co-authored; force rests on §17.17.3; §17.17.2 classification-mandatory-before-ship) → spec §9.7.4.1 item 3a (residence RULE — canonical), §9 (~:187), §3.10.6/§3.10.8/§3.10.12; ADR-054 **Proposed** (realization in RFC #2130 — out of scope) → ADR-052 + construction.md M1–M5 (M2 updated), ADR-048/049, ADR-006/025/055/057 → #627/#1518/#1880, #1733 (folded for custody/attestation/DHT/storage), RFC #2130 / #1729 / #1777 (pre-rotation) → source anchors: **E1/D-A** `scp-identity/src/dht.rs:222/264/270` (default type param, `impl Default`, `new()`) + `config.rs` + `Cargo.toml:16`; `scp-node/src/self_host.rs:1883` (`build_memory_did_method`), `lib.rs`, `config.rs:210/391` (`DhtMode`), `Cargo.toml`; `scp-runtime/src/discovery/{dht_context.rs:237-489,did_capabilities.rs:198-466}`; `scp-ffi/common/src/{server.rs:35/322/435/455,resolvers.rs:1025,bridge_instance.rs:358}`; uniffi `bridge.rs:3912/8063/9010/9130/16714`. **E5 (out of scope — tracked)** `pre_rotation_custody` field welds `scp-ffi/src/identity.rs`,`napi/src/identity.rs`,`uniffi/src/bridge.rs`; `traits.rs:740` (`PreRotationCustody`). **E2/E3/E4** `credentials.rs:502/556`,`napi/runtime.rs:313`; `storage.rs:480/561`; E4 READ `resolver.rs:309` (`NoOpRelayQuerier`), `:910` (`InMemoryRelayQuerier` test); E4 WRITE `scp-identity/src/republish.rs:104` (`RelayPublisher` trait), `:156/:186` (`InMemoryRelayPublisher`), `:397` (`RepublishManager<R = InMemoryRelayPublisher>` default type param — the ADR-062 sever target); `:703` (republish loop drops signature/sequence, publishes bare `document_bytes` not the identity-record frame — #482 fix, out of ADR-062 scope); identity-record frame primitive → `scp-protocol` (§3.10.12 Phase-2 type, §9.10.12; built under #482). **switch/F1** `scp-ffi/src/custody.rs:35/38`,`napi/src/scp.rs:379`; `scp-ffi-common/Cargo.toml:30`; `scp-ffi/Cargo.toml:27,51`,`napi:15,55`,`uniffi:32,63,66`; `scp-testing/Cargo.toml`,`scp-protocol/Cargo.toml:47`; `bridge_runtime.rs:166,275,285,315`; `scp-dht dht_client/mod.rs:93`; `bridge.rs:3622`; CLAUDE.md clippy string + `.github/workflows/{ci,release}.yml`.
````

Live text after the cut:

````text
§17.17 (co-authored; force rests on §17.17.3; §17.17.2 classification-mandatory-before-ship) → spec §9.7.4.1 item 3a (residence RULE — canonical), §9 (~:187), §3.10.6/§3.10.8/§3.10.12; ADR-054 **Proposed** (realization in RFC #2130 — out of scope) → ADR-052 + construction.md M1–M5 (M2 updated), ADR-048/049, ADR-006/025/055/057 → #627/#1518/#1880, #1733 (folded for custody/attestation/DHT/storage), RFC #2130 / #1729 / #1777 (pre-rotation) → source anchors: **E1/D-A** `scp-identity/src/dht.rs:222/264/270` (default type param, `impl Default`, `new()`) + `config.rs` + `Cargo.toml:16`; `scp-node/src/self_host.rs:1883` (`build_memory_did_method`), `lib.rs`, `config.rs:210/391` (`DhtMode`), `Cargo.toml`; `scp-runtime/src/discovery/{dht_context.rs:237-489,did_capabilities.rs:198-466}`; `scp-ffi/common/src/{server.rs:35/322/435/455,resolvers.rs:1025,bridge_instance.rs:358}`; uniffi `bridge.rs:3912/8063/9010/9130/16714`. **E5 (out of scope — tracked)** `pre_rotation_custody` field welds `scp-ffi/src/identity.rs`,`napi/src/identity.rs`,`uniffi/src/bridge.rs`; `traits.rs:740` (`PreRotationCustody`). **E3/E4** `storage.rs:480/561`; E4 READ `resolver.rs:309` (`NoOpRelayQuerier`), `:910` (`InMemoryRelayQuerier` test); E4 WRITE `scp-identity/src/republish.rs:104` (`RelayPublisher` trait), `:156/:186` (`InMemoryRelayPublisher`), `:397` (`RepublishManager<R = InMemoryRelayPublisher>` default type param — the ADR-062 sever target); `:703` (republish loop drops signature/sequence, publishes bare `document_bytes` not the identity-record frame — #482 fix, out of ADR-062 scope); identity-record frame primitive → `scp-protocol` (§3.10.12 Phase-2 type, §9.10.12; built under #482). **switch/F1** `scp-ffi/src/custody.rs:35/38`,`napi/src/scp.rs:379`; `scp-ffi-common/Cargo.toml:30`; `scp-ffi/Cargo.toml:27,51`,`napi:15,55`,`uniffi:32,63,66`; `scp-testing/Cargo.toml`,`scp-protocol/Cargo.toml:47`; `bridge_runtime.rs:166,275,285,315`; `scp-dht dht_client/mod.rs:93`; `bridge.rs:3622`; CLAUDE.md clippy string + `.github/workflows/{ci,release}.yml`.
````

## `.docs/prds/main.json`, the entry `gate-5`, line 149 on main when archived

````text
      "name": "Phase 5: Platform Adapters + Swift + Bridges + Media",
````

Live text after the cut:

````text
      "name": "Phase 5: Platform Adapters + Swift + Media",
````

## `.docs/prds/main.json`, the entry `gate-5`, lines 153–157 on main when archived

````text
        "SCP-084",
        "SCP-085",
        "SCP-086",
        "SCP-087",
        "SCP-088",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-081`, line 4663 on main when archived

````text
        "bindings/typescript/src/bridge.ts",
````

Live text after the cut:

````text
        "bindings/typescript/src/internal/bridge.ts",
````

## `.docs/prds/main.json`, the entry `SCP-081`, line 4681 on main when archived

````text
        "Create bindings/typescript/src/bridge.ts exposing the napi backend",
````

Live text after the cut:

````text
        "Create bindings/typescript/src/internal/bridge.ts exposing the napi backend",
````

## `.docs/prds/main.json`, the entries `SCP-084`, `SCP-085`, `SCP-086`, `SCP-087`, `SCP-088`, lines 4830–5101 on main when archived

````text
    {
      "id": "SCP-084",
      "title": "Define bridge core types and module structure",
      "gate": "gate-5",
      "priority": "P1",
      "severity": "critical",
      "status": "done",
      "files": [
        "crates/scp-core/src/bridge/mod.rs"
      ],
      "description": "Create the `scp-core/bridge/` module root with all bridge protocol types from ADR-023. Bridge connector as registered protocol entity with accountable operator identifier. Shadow identities as restricted participants (observer default). Four operating modes (Relay, Puppet, Api, Cooperative). All bridged content carries full provenance chain.\n\nKey types:\n\n```rust\npub struct BridgeConnector {\n    pub bridge_id: String,\n    pub operator_did: DID,\n    pub platform: String,\n    pub mode: BridgeMode,\n    pub status: BridgeStatus,\n    pub registration_context: ContextId,\n    pub registered_at: u64,\n}\n\npub enum BridgeMode {\n    Relay,        // Read-only mirroring from external platform\n    Puppet,       // Bridge acts on behalf of external users\n    Api,          // Platform API integration\n    Cooperative,  // Native SCP support on external platform\n}\n\npub enum BridgeStatus {\n    Active,\n    Suspended,\n    Revoked,\n}\n\npub struct ShadowIdentity {\n    pub shadow_id: String,\n    pub platform_handle: String,\n    pub bridge_id: String,\n    pub attributed_role: String,     // Default: \"observer\"\n    pub provenance_status: ShadowProvenanceStatus,\n    pub created_at: u64,\n}\n\npub enum ShadowProvenanceStatus {\n    Shadow,   // Unclaimed — attributed via bridge\n    Claimed,  // Bound to an identifier via identity attestation\n}\n```\n\nModule declares `pub mod registration; pub mod shadow; pub mod claiming; pub mod provenance;` and re-exports all public types.",
      "acceptanceCriteria": [
        "`cargo build -p scp-core` succeeds with zero warnings",
        "BridgeConnector struct has fields: bridge_id (String), operator_did (DID), platform (String), mode (BridgeMode), status (BridgeStatus), registration_context (ContextId), registered_at (u64)",
        "BridgeMode enum has variants: Relay, Puppet, Api, Cooperative",
        "BridgeStatus enum has variants: Active, Suspended, Revoked",
        "ShadowIdentity struct has fields: shadow_id (String), platform_handle (String), bridge_id (String), attributed_role (String), provenance_status (ShadowProvenanceStatus), created_at (u64)",
        "ShadowProvenanceStatus enum has variants: Shadow, Claimed",
        "mod.rs declares pub mod for registration, shadow, claiming, provenance",
        "All public items have /// doc comments",
        "All types derive Debug, Clone, serde::Serialize, serde::Deserialize"
      ],
      "actionItems": [
        "Create crates/scp-core/src/bridge/mod.rs with BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity, ShadowProvenanceStatus",
        "Add pub mod declarations for registration, shadow, claiming, provenance sub-modules (empty stubs)",
        "Add re-exports for all public types",
        "Add pub mod bridge to scp-core/src/lib.rs",
        "Verify cargo build and clippy pass"
      ],
      "blockedBy": [],
      "sources": [
        {
          "file": ".docs/adrs/phase-5.md",
          "section": "## ADR-023: Bridge Connector Protocol"
        }
      ],
      "details": {
        "adr": "ADR-023",
        "protocolSection": "§12",
        "keyTypes": {
          "BridgeConnector": "bridge_id, operator_did, platform, mode, status, registration_context, registered_at",
          "BridgeMode": "Relay | Puppet | Api | Cooperative",
          "BridgeStatus": "Active | Suspended | Revoked",
          "ShadowIdentity": "shadow_id, platform_handle, bridge_id, attributed_role, provenance_status, created_at",
          "ShadowProvenanceStatus": "Shadow | Claimed"
        }
      },
      "result": "BridgeConnector, BridgeMode, BridgeStatus, ShadowIdentity, ShadowProvenanceStatus. Stub submodules. 12 tests."
    },
    {
      "id": "SCP-085",
      "title": "Implement bridge registration with governance approval",
      "gate": "gate-5",
      "priority": "P1",
      "severity": "critical",
      "status": "done",
      "files": [
        "crates/scp-core/src/bridge/registration.rs"
      ],
      "description": "Implement bridge registration in `scp-core/bridge/registration.rs`. Operator identifier presents registration request to context governance. Context governance approves or rejects. Registered bridge visible in context metadata (visible before opt-in, per legibility tenet). Registration is a context event in the Merkle log.\n\nBridge revocation: context governance removes bridge at any time. Severing bridge disconnects all shadow identities from external platform. Shadows retain their attributed actions but can no longer receive/send.\n\nContext isolation: bridge in Context A has zero access to Context B. Same platform bridged into two contexts = two separate bridge instances with separate registrations.\n\nSelf-hosted bridges: protocol treats self-hosted and managed identically. Self-hosted eliminates third-party credential delegation (puppet mode).",
      "acceptanceCriteria": [
        "Operator identifier presents registration request to context governance",
        "Context governance approves or rejects registration",
        "Registered bridge visible in context metadata (visible before opt-in, per legibility tenet)",
        "Registration is a context event in the Merkle log",
        "Context governance removes bridge at any time (revocation)",
        "Severing bridge disconnects all shadow identities from external platform",
        "Shadows retain their attributed actions but can no longer receive/send after revocation",
        "Bridge in Context A has zero access to Context B (context isolation)",
        "Same platform bridged into two contexts = two separate bridge instances with separate registrations",
        "Protocol treats self-hosted and managed bridges identically",
        "Self-hosted eliminates third-party credential delegation (puppet mode)",
        "`cargo test -p scp-core` passes all bridge registration tests"
      ],
      "actionItems": [
        "Implement register_bridge(operator_did, platform, mode, context) -> Result<BridgeConnector, BridgeError>",
        "Implement approve_registration(bridge_id, governance_decision) -> Result<BridgeConnector, BridgeError>",
        "Implement revoke_bridge(bridge_id, governance_action) -> Result<(), BridgeError>",
        "Implement list_bridges(context_id) -> Vec<BridgeConnector> for context metadata visibility",
        "Emit context events for registration and revocation into event log",
        "Enforce context isolation — bridge instance scoped to single context",
        "Write unit tests for registration, approval, rejection, revocation, context isolation"
      ],
      "blockedBy": [
        "SCP-084",
        "SCP-018",
        "SCP-030"
      ],
      "sources": [
        {
          "file": ".docs/adrs/phase-5.md",
          "section": "### Acceptance Criteria"
        }
      ],
      "details": {
        "adr": "ADR-023",
        "acceptanceCriteriaRefs": [
          "2. Bridge registration",
          "9. Bridge revocation",
          "10. Context isolation",
          "11. Self-hosted bridges"
        ],
        "dependencies": {
          "ADR-008": "Bridge registration requires context governance approval. Bridge revocation is a governance action.",
          "ADR-011": "Bridge registration, shadow creation, and claiming are context events."
        }
      },
      "result": "Bridge registration with governance approval/revocation, context isolation. 44 tests."
    },
    {
      "id": "SCP-086",
      "title": "Implement shadow identity creation and role management",
      "gate": "gate-5",
      "priority": "P1",
      "severity": "critical",
      "status": "done",
      "files": [
        "crates/scp-core/src/bridge/shadow.rs"
      ],
      "description": "Implement shadow identity creation and role management in `scp-core/bridge/shadow.rs`. Bridge creates protocol entity per external platform participant. Shadow carries platform handle, bridge reference, and operating mode.\n\nShadow default role: observer-equivalent with restricted capabilities. Cannot exercise capabilities requiring verified identity. Specific role upgradeable by context governance.\n\nShadow creation is a context event in the Merkle log.",
      "acceptanceCriteria": [
        "Bridge creates protocol entity per external platform participant",
        "Shadow carries platform handle, bridge reference, and operating mode",
        "Shadow default role is observer-equivalent with restricted capabilities",
        "Shadows cannot exercise capabilities requiring verified identity",
        "Specific role upgradeable by context governance",
        "Shadow creation is a context event in the Merkle log",
        "`cargo test -p scp-core` passes all shadow identity tests"
      ],
      "actionItems": [
        "Implement create_shadow(bridge_id, platform_handle) -> Result<ShadowIdentity, BridgeError>",
        "Enforce observer default role on shadow creation",
        "Implement upgrade_shadow_role(shadow_id, new_role, governance_action) -> Result<(), BridgeError>",
        "Implement list_shadows(bridge_id) -> Vec<ShadowIdentity>",
        "Emit shadow creation event to context event log",
        "Write unit tests for shadow creation, default role enforcement, role upgrade"
      ],
      "blockedBy": [
        "SCP-084",
        "SCP-023",
        "SCP-030"
      ],
      "sources": [
        {
          "file": ".docs/adrs/phase-5.md",
          "section": "### Acceptance Criteria"
        }
      ],
      "details": {
        "adr": "ADR-023",
        "acceptanceCriteriaRefs": [
          "3. Shadow identity creation",
          "4. Shadow default role"
        ],
        "dependencies": {
          "ADR-011": "Shadow creation is a context event.",
          "ADR-009": "Role management uses context governance roles."
        }
      },
      "result": "Already implemented in prior iteration. ShadowRegistry with create_shadow, role management, collision guard, 62 shadow-specific tests."
    },
    {
      "id": "SCP-087",
      "title": "Implement BridgeProvenance for bridged content attribution",
      "gate": "gate-5",
      "priority": "P1",
      "severity": "critical",
      "status": "done",
      "files": [
        "crates/scp-core/src/bridge/provenance.rs"
      ],
      "description": "Implement BridgeProvenance and provenance marking for all bridged content in `scp-core/bridge/provenance.rs`.\n\nAll actions/content attributed to shadow identities carry `BridgeProvenance`. `BridgeProvenance` includes: originating platform, bridge connector ID, operator identifier, operating mode, shadow/claimed status. No shadow action mistakable for native SCP action.\n\nTrust hierarchy (two axes per §12.5):\n- Native identity + native transport (strongest).\n- Native identity + bridged transport.\n- Claimed shadow + historical bridged.\n- Shadow + bridged (weakest).\n- Both identity confidence and transport confidence factor into evaluation.\n\nKey type:\n\n```rust\n/// Extension of DataProvenance for bridged content.\npub struct BridgeProvenance {\n    pub base: DataProvenance,\n    pub originating_platform: String,\n    pub bridge_connector_id: String,\n    pub operator_did: DID,\n    pub bridge_mode: BridgeMode,\n    pub shadow_status: ShadowProvenanceStatus,\n}\n```",
      "acceptanceCriteria": [
        "BridgeProvenance struct extends DataProvenance with fields: originating_platform, bridge_connector_id, operator_did, bridge_mode, shadow_status",
        "All actions/content attributed to shadow identities carry BridgeProvenance",
        "BridgeProvenance includes: originating platform, bridge connector ID, operator identifier, operating mode, shadow/claimed status",
        "No shadow action mistakable for native SCP action",
        "Trust hierarchy implements four levels: native+native (strongest), native+bridged, claimed+bridged, shadow+bridged (weakest)",
        "Both identity confidence and transport confidence factor into trust evaluation",
        "`cargo test -p scp-core` passes all bridge provenance tests"
      ],
      "actionItems": [
        "Implement BridgeProvenance struct extending DataProvenance",
        "Implement mark_bridge_provenance(action, bridge, shadow) -> BridgeProvenance",
        "Implement trust_level(provenance) -> TrustLevel with four-tier hierarchy",
        "Implement is_native_action(provenance) -> bool to distinguish native from bridged",
        "Write unit tests for provenance marking, trust hierarchy ordering, native vs bridged distinction"
      ],
      "blockedBy": [
        "SCP-084"
      ],
      "sources": [
        {
          "file": ".docs/adrs/phase-5.md",
          "section": "### Acceptance Criteria"
        }
      ],
      "details": {
        "adr": "ADR-023",
        "acceptanceCriteriaRefs": [
          "5. Provenance marking",
          "6. Trust hierarchy"
        ],
        "dependencies": {
          "ADR-019": "All bridged content carries BridgeProvenance extending DataProvenance."
        },
        "trustHierarchy": [
          "Native identity + native transport (strongest)",
          "Native identity + bridged transport",
          "Claimed shadow + historical bridged",
          "Shadow + bridged (weakest)"
        ]
      },
      "result": "Bridge provenance with 4-tier trust hierarchy. 34 new tests."
    },
    {
      "id": "SCP-088",
      "title": "Implement shadow claiming with identity attestation",
      "gate": "gate-5",
      "priority": "P1",
      "severity": "critical",
      "status": "done",
      "files": [
        "crates/scp-core/src/bridge/claiming.rs"
      ],
      "description": "Implement shadow claiming via identity attestation in `scp-core/bridge/claiming.rs`. Shadow claiming via identity attestation (§3.5) is one-way and irreversible.\n\nClaimant publishes identity attestation (§3.5) binding external handle to identifier. Protocol verifies attestation matches shadow's platform handle. Shadow retired, historical actions retroattributed to claimant identifier.\n\nClaiming is one-way and irreversible: claimed shadow cannot be unclaimed. Claimed shadow cannot be re-assigned to a different identifier.\n\nClaiming is a context event in the Merkle log.\n\nKey types:\n\n```rust\npub struct ClaimRequest {\n    pub shadow_id: String,\n    pub claimant_did: DID,\n    pub platform_handle: String,\n    pub identity_attestation: Attestation,  // §3.5 attestation binding handle to identifier\n    pub timestamp: u64,\n    pub signature: Ed25519Signature,\n}\n\n// claim_shadow returns Result<ShadowClaimEvent, ClaimError>\n\npub enum ClaimError {\n    HandleMismatch,\n    AttestationInvalid,\n    AlreadyClaimed,\n    ShadowNotFound,\n}\n```",
      "acceptanceCriteria": [
        "ClaimRequest struct has fields: shadow_id, claimant_did, platform_handle, identity_attestation (Attestation per §3.5), timestamp, signature (Ed25519Signature)",
        "claim_shadow returns Result<ShadowClaimEvent, ClaimError>",
        "ClaimError enum has variants: HandleMismatch, AttestationInvalid, AlreadyClaimed, ShadowNotFound",
        "Claimant publishes identity attestation (§3.5) binding external handle to identifier",
        "Protocol verifies attestation matches shadow's platform handle",
        "Shadow retired, historical actions retroattributed to claimant identifier",
        "Claimed shadow cannot be unclaimed (one-way)",
        "Claimed shadow cannot be re-assigned to a different identifier (irreversible)",
        "Claiming is a context event in the Merkle log",
        "`cargo test -p scp-core` passes all shadow claiming tests"
      ],
      "actionItems": [
        "Implement ClaimRequest, ClaimError types",
        "Implement claim_shadow(registry, request: ClaimRequest) -> Result<ShadowClaimEvent, ClaimError>",
        "Verify attestation matches shadow's platform handle",
        "Implement retroattribute_actions(shadow_id, claimant_did) to retroattribute historical actions",
        "Enforce one-way irreversibility: reject unclaim and re-assignment attempts",
        "Emit claiming event to context event log",
        "Write unit tests for successful claim, handle mismatch, invalid attestation, already-claimed rejection, shadow-not-found"
      ],
      "blockedBy": [
        "SCP-084",
        "SCP-086",
        "SCP-006",
        "SCP-030"
      ],
      "sources": [
        {
          "file": ".docs/adrs/phase-5.md",
          "section": "### Acceptance Criteria"
        }
      ],
      "details": {
        "adr": "ADR-023",
        "acceptanceCriteriaRefs": [
          "7. Shadow claiming",
          "8. Claiming is one-way and irreversible"
        ],
        "dependencies": {
          "ADR-003": "Shadow claiming uses identity attestation (§3.5) to bind external handle to identifier.",
          "ADR-011": "Claiming is a context event."
        }
      },
      "result": "Created crates/scp-core/src/bridge/claiming.rs with ClaimRequest, ClaimError types and claim_shadow() function. One-way irreversible claiming with attestation verification."
    },
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, line 6014 on main when archived

````text
      "title": "Phase 5 end-to-end integration test across all four ADRs",
````

Live text after the cut:

````text
      "title": "Phase 5 end-to-end integration test across all three ADRs",
````

## `.docs/prds/main.json`, the entry `SCP-104`, line 6022 on main when archived

````text
      "description": "Phase 5 end-to-end integration test validating all four ADRs work together. Tests the full bridge-to-media-to-platform-to-SDK pipeline:\n\n1. **Bridge (ADR-023):** Register bridge, create shadow identity, bridge message with provenance, claim shadow, verify retroattribution.\n2. **Media (ADR-024):** Initiate media session with capability ceiling check, export MLS keys, exchange signaling messages, end session, verify event log.\n3. **Apple Platform (ADR-025):** Key custody operations through Secure Enclave/Keychain adapters, App Attest attestation, APNs push registration.\n4. **Swift SDK (ADR-026):** Identity create/load, context create/join/send/receive/leave, outlet invocation, UCAN validation — all through Swift wrapper layer.\n\nThis test validates that Phase 5 components integrate with Phase 1-4 foundation (MLS, envelope, identifier, context, UCAN, transport, event log, provenance, UniFFI).",
````

Live text after the cut:

````text
      "description": "Phase 5 end-to-end integration test validating all three ADRs work together. Tests the full media-to-platform-to-SDK pipeline:\n\n1. **Media (ADR-024):** Initiate media session with capability ceiling check, export MLS keys, exchange signaling messages, end session, verify event log.\n2. **Apple Platform (ADR-025):** Key custody operations through Secure Enclave/Keychain adapters, App Attest attestation, APNs push registration.\n3. **Swift SDK (ADR-026):** Identity create/load, context create/join/send/receive/leave, outlet invocation, UCAN validation — all through Swift wrapper layer.\n\nThis test validates that Phase 5 components integrate with Phase 1-4 foundation (MLS, envelope, identifier, context, UCAN, transport, event log, provenance, UniFFI).",
````

## `.docs/prds/main.json`, the entry `SCP-104`, line 6024 on main when archived

````text
        "Bridge registration, shadow creation, provenance marking, and claiming all succeed end-to-end",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, line 6028 on main when archived

````text
        "Bridged content carries correct BridgeProvenance through entire pipeline",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, line 6036 on main when archived

````text
        "Test bridge lifecycle: register -> shadow -> message -> claim -> retroattribute",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, line 6040 on main when archived

````text
        "Verify cross-ADR integration: bridged media session, platform-backed identity in bridge claim",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, lines 6044–6048 on main when archived

````text
        "SCP-084",
        "SCP-085",
        "SCP-086",
        "SCP-087",
        "SCP-088",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, line 6068 on main when archived

````text
          "section": "# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK"
````

Live text after the cut:

````text
          "section": "# Phase 5 Architecture Decision Records — Media, Apple Platform, Swift SDK"
````

## `.docs/prds/main.json`, the entry `SCP-104`, line 6073 on main when archived

````text
          "ADR-023",
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-104`, line 6085 on main when archived

````text
      "result": "Phase 5 integration test created at crates/scp-core/tests/phase5_integration.rs with 11 tests covering bridge lifecycle (ADR-023), media lifecycle (ADR-024), platform adapters (ADR-025), and cross-ADR integration. All tests pass. Swift SDK tests (ACs 4, 9) deferred to XCFramework build (SCP-103)."
````

Live text after the cut:

````text
      "result": "Phase 5 integration test created at crates/scp-core/tests/phase5_integration.rs with 8 tests covering media lifecycle (ADR-024), platform adapters (ADR-025), and cross-ADR integration. All tests pass. Swift SDK tests (ACs 4, 9) deferred to XCFramework build (SCP-103)."
````

## `.docs/prds/main.json`, the entry `SCP-216`, line 9961 on main when archived

These lines labelled the Swift SDK receive decision "ADR-023". That decision is ADR-026, Swift SDK, in `phase-5.md`. The TypeScript and Kotlin labels in the same sentence named ADR-019, Data Provenance, and ADR-027, Android Platform Adapter; the decisions they cite are ADR-022, TypeScript SDK, and ADR-028, Kotlin SDK. The S1 pull request corrected all three labels because ADR-023 left the live documents.

````text
      "description": "The Python receive() iterator (py_context_receive / PyMessageReceiver.__anext__) has placeholder semantics that conflate empty and closed channels. The __anext__ method uses sync try_recv() and maps both TryRecvError::Empty and TryRecvError::Disconnected to StopAsyncIteration. The sender _tx is dropped immediately after channel creation, meaning the channel is always disconnected.\n\nNo spec, ADR, or PRD story captures the intended lifecycle semantics. ADR-014 has only a function signature (line 291-293). By contrast, TypeScript (ADR-019 phase-4.md) specifies full onMessage/onError/onComplete callbacks, Swift (ADR-023 phase-5.md) specifies AsyncStream with continuation.yield/finish, and Kotlin (ADR-027 phase-6.md) specifies callbackFlow/awaitClose. sketch.md (lines 371-389) specifies AsyncStream<ContextEvent>, 1000-event buffer, oldest-drop overflow, and BufferOverflow warning event.\n\nThis story adds the missing lifecycle specification to ADR-014 and implements it.",
````

Live text after the cut:

````text
      "description": "The Python receive() iterator (py_context_receive / PyMessageReceiver.__anext__) has placeholder semantics that conflate empty and closed channels. The __anext__ method uses sync try_recv() and maps both TryRecvError::Empty and TryRecvError::Disconnected to StopAsyncIteration. The sender _tx is dropped immediately after channel creation, meaning the channel is always disconnected.\n\nNo spec, ADR, or PRD story captures the intended lifecycle semantics. ADR-014 has only a function signature (line 291-293). By contrast, TypeScript (ADR-022 phase-4.md) specifies full onMessage/onError/onComplete callbacks, Swift (ADR-026 phase-5.md) specifies AsyncStream with continuation.yield/finish, and Kotlin (ADR-028 phase-6.md) specifies callbackFlow/awaitClose. sketch.md (lines 371-389) specifies AsyncStream<ContextEvent>, 1000-event buffer, oldest-drop overflow, and BufferOverflow warning event.\n\nThis story adds the missing lifecycle specification to ADR-014 and implements it.",
````

## `.docs/prds/main.json`, the entry `SCP-216`, lines 9995–9998 on main when archived

````text
        {
          "file": ".docs/adrs/phase-5.md",
          "section": "## ADR-023: Bridge Connector Protocol"
        },
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/main.json`, the entry `SCP-302`, line 10509 on main when archived

````text
      "description": "ADR-059 and §7.2.4 decide that capability/trust validation crosses the FFI as a typed structured record (CapabilityValidation: six per-stage booleans) and that SDKs MUST consume that result — never reverse-engineer which check failed by parsing human-readable error prose. The structured bridge op (ucan_evaluate / evaluate_ucan returning CapabilityValidation) already exists at the Rust core and all three FFI bridges; only the SDK consumers are wrong. A first-principles audit of the trust/capability SDK surface found the Python SDK string-matching error prose in trust.py to reconstruct the per-check breakdown, an antipattern that is brittle by construction and that masked a multi-attestation nonce bug (mocks emitted prose without modeling nonce state). This story is the C3c SDK rebuild: delete the Python prose-classification apparatus and consume the structured ucan_evaluate op; add the TypeScript public evaluateTrust wrapper over a ucanEvaluate bridge call plumbed through all TS bridge layers, exposing a CapabilityValidation interface, with all bridge-error typing routed through a single mapping chokepoint keyed on the [SCP-CAT-NNNN] error-code taxonomy rather than per-call prose classification; and rebuild the test mocks to model nonce state so the masked-bug class is surfaced. Per ADR-059 §Decision-5 and the per-SDK-idiom lesson, ALL FOUR bindings expose an idiomatic wrapper over the structured result: the per-SDK-idiom lesson governs HOW each binding surfaces the op (language-native naming/types), never WHETHER it does. The UniFFI bridge already exports CapabilityValidationRecord, so the Swift and Kotlin SDKs add the idiomatic sugar (SCP.ucanEvaluate / evaluateTrust plus a CapabilityValidation type) on top of it, at parity with Python and TypeScript. This story also lands the bundled SDK-parity wrappers the same audit identified as missing on the affected SDKs (per the UCAN.evaluate / Trust.evaluate_trust / Bridge.* / Identity.* / Discovery.discover / Economy.verify_payment_receipts capability-matrix exemptions that name \"the C3c SDK-parity follow-up\"). Per-SDK idiom is preserved throughout; the structured-result field set is identical across bindings (snake_case in Python, camelCase in TypeScript), only the wrappers are language-idiomatic.",
````

Live text after the cut:

````text
      "description": "ADR-059 and §7.2.4 decide that capability/trust validation crosses the FFI as a typed structured record (CapabilityValidation: six per-stage booleans) and that SDKs MUST consume that result — never reverse-engineer which check failed by parsing human-readable error prose. The structured bridge op (ucan_evaluate / evaluate_ucan returning CapabilityValidation) already exists at the Rust core and all three FFI bridges; only the SDK consumers are wrong. A first-principles audit of the trust/capability SDK surface found the Python SDK string-matching error prose in trust.py to reconstruct the per-check breakdown, an antipattern that is brittle by construction and that masked a multi-attestation nonce bug (mocks emitted prose without modeling nonce state). This story is the C3c SDK rebuild: delete the Python prose-classification apparatus and consume the structured ucan_evaluate op; add the TypeScript public evaluateTrust wrapper over a ucanEvaluate bridge call plumbed through all TS bridge layers, exposing a CapabilityValidation interface, with all bridge-error typing routed through a single mapping chokepoint keyed on the [SCP-CAT-NNNN] error-code taxonomy rather than per-call prose classification; and rebuild the test mocks to model nonce state so the masked-bug class is surfaced. Per ADR-059 §Decision-5 and the per-SDK-idiom lesson, ALL FOUR bindings expose an idiomatic wrapper over the structured result: the per-SDK-idiom lesson governs HOW each binding surfaces the op (language-native naming/types), never WHETHER it does. The UniFFI bridge already exports CapabilityValidationRecord, so the Swift and Kotlin SDKs add the idiomatic sugar (SCP.ucanEvaluate / evaluateTrust plus a CapabilityValidation type) on top of it, at parity with Python and TypeScript. This story also lands the bundled SDK-parity wrappers the same audit identified as missing on the affected SDKs (per the UCAN.evaluate / Trust.evaluate_trust / Identity.* / Discovery.discover / Economy.verify_payment_receipts capability-matrix exemptions that name \"the C3c SDK-parity follow-up\"). Per-SDK idiom is preserved throughout; the structured-result field set is identical across bindings (snake_case in Python, camelCase in TypeScript), only the wrappers are language-idiomatic.",
````

## `.docs/prds/main.json`, the entry `SCP-302`, lines 10514–10515 on main when archived

````text
        "The bundled SDK-parity wrappers land on the SDKs the audit flagged: TypeScript public Identity wrappers identityRotateKey, identityAddAgentKey, identityRotateAgentKey, identityRemoveAgentKey, and identityMigrate exist on the SCP class (the bare rotateKey/addAgentKey/rotateAgentKey/removeAgentKey/migrate names are the underlying Identity-handle methods, not the SCP-class wrappers); a TypeScript public bridgeRegister wrapper exists as a module-level export in bindings/typescript/src/bridge.ts re-exported from bindings/typescript/src/index.ts (the TS free-function idiom — NOT a method on the SCP class); a Python public discover() method exists in bindings/python/scp_sdk/discovery.py; and a Python public verify_payment_receipts() method exists in bindings/python/scp_sdk/economy.py",
        "The capability matrix .docs/standards/sdk-capability-matrix.json flips these cells true and removes the now-stale C3c-follow-up exemption for each flipped cell: UCAN.evaluate (python, typescript, kotlin, and swift all true, with the kotlin and swift C3c-follow-up exemptions removed), Trust.evaluate_trust (typescript true), Bridge.evaluate_trust (typescript true), Identity.rotate_key / Identity.add_agent_key / Identity.rotate_agent_key / Identity.remove_agent_key / Identity.migrate (typescript true), Bridge.register (typescript true), Discovery.discover (python true), and Economy.verify_payment_receipts (python true); the (\"UCAN\", \"evaluate\") alias in the ALIASES table of scripts/check-sdk-coverage.py lists all four bindings (python: ucan_evaluate/evaluate_trust, typescript: ucanEvaluate/evaluateTrust, kotlin: ucanEvaluate/evaluateTrust, swift: ucanEvaluate/evaluateTrust); and python3.12 scripts/check-sdk-coverage.py exits 0",
````

Live text after the cut:

````text
        "The bundled SDK-parity wrappers land on the SDKs the audit flagged: TypeScript public Identity wrappers identityRotateKey, identityAddAgentKey, identityRotateAgentKey, identityRemoveAgentKey, and identityMigrate exist on the SCP class (the bare rotateKey/addAgentKey/rotateAgentKey/removeAgentKey/migrate names are the underlying Identity-handle methods, not the SCP-class wrappers); a Python public discover() method exists in bindings/python/scp_sdk/discovery.py; and a Python public verify_payment_receipts() method exists in bindings/python/scp_sdk/economy.py",
        "The capability matrix .docs/standards/sdk-capability-matrix.json flips these cells true and removes the now-stale C3c-follow-up exemption for each flipped cell: UCAN.evaluate (python, typescript, kotlin, and swift all true, with the kotlin and swift C3c-follow-up exemptions removed), Trust.evaluate_trust (typescript true), Identity.rotate_key / Identity.add_agent_key / Identity.rotate_agent_key / Identity.remove_agent_key / Identity.migrate (typescript true), Discovery.discover (python true), and Economy.verify_payment_receipts (python true); the (\"UCAN\", \"evaluate\") alias in the ALIASES table of scripts/check-sdk-coverage.py lists all four bindings (python: ucan_evaluate/evaluate_trust, typescript: ucanEvaluate/evaluateTrust, kotlin: ucanEvaluate/evaluateTrust, swift: ucanEvaluate/evaluateTrust); and python3.12 scripts/check-sdk-coverage.py exits 0",
````

## `.docs/prds/main.json`, the entry `SCP-302`, line 10535 on main when archived

````text
        "Add the bundled SDK-parity wrappers: TS SCP-class Identity wrappers identityRotateKey/identityAddAgentKey/identityRotateAgentKey/identityRemoveAgentKey/identityMigrate; the module-level bridgeRegister free-function export (bindings/typescript/src/bridge.ts, re-exported from index.ts — NOT an SCP-class method); Python discover() in discovery.py and verify_payment_receipts() in economy.py",
````

Live text after the cut:

````text
        "Add the bundled SDK-parity wrappers: TS SCP-class Identity wrappers identityRotateKey/identityAddAgentKey/identityRotateAgentKey/identityRemoveAgentKey/identityMigrate; Python discover() in discovery.py and verify_payment_receipts() in economy.py",
````

## `.docs/prds/adr062-capability-injection.json`, the PRD description, line 3 on main when archived

````text
  "description": "Realization of ADR-062 (applying umbrella spec §17.17 unchanged), scoped to capabilities that have a real backend TODAY. Every in-memory NULLIFIER with a real backend (key custody -> File/Sqlite/callback; device attestation -> declined per spec §9:187; identity resolution -> Pkarr) becomes a test-harness-only double gated `#[cfg(feature = \"testing\")]`, provably absent from shipped artifacts via G1's SOLE closed subset-allowlist; durability-only arms (storage, push, blob) stay legitimate explicit runtime options, never Default. The allow_in_memory_custody switch, the public custody=in_memory config, and the DidDht<D=InMemoryDhtClient> nullifier-default type parameter are all deleted. E4 relay layer: NoOpRelayQuerier (READ) is NOT a nullifier — it fails CLOSED (Ok(None), never a false document) and ships honestly, UNCHANGED, as the DHT-only interim. Slice 11's ONLY scope is the E4 WRITE-path default-selection hygiene fix: sever the InMemoryRelayPublisher default type param on RepublishManager (republish.rs:397) + demote InMemoryRelayPublisher to #[cfg(any(test, feature=\"testing\"))], matching E1/E2/E3. Building relay resolution itself — the real MultiRelayQuerier, a real RelayPublisher, the key-event-record frame (§9.10.12), relay-side validation, and the republish-loop signature/sequence-drop fix (republish.rs:703) — is issue #482 (a FEATURE; spec §3.10.2/§3.10.4/§3.10.8, §9.10.12), OUT of ADR-062 scope and storied under .docs/prds/relay-did-resolution.json. PRE-ROTATION CUSTODY IS OUT OF SCOPE: production realization is punted to a later e2e-collab stage (RFC #2130 / #1729 / #1777); ADR-054 is Proposed, only the §3a residence RULE is canonical (spec §9.7.4.1 item 3a). Because no real pre-rotation backend is built now, Slice 6 severs the InMemoryPreRotationCustody NULLIFIER to test-harness-only (#[cfg(feature=\"testing\")], folded into `testing` like custody/attestation — NO standalone allowlisted feature) and makes production identity creation FAIL CLOSED with a typed error rather than fall back to the nullifier. G1 allowlists durability-only + real-backend features — ZERO nullifiers, no exceptions (PR #2132). Only the real pre-rotation BACKEND is out of scope (RFC #2130 / #1729); whether identities may be created without a pre-rotation commitment is #1553. Six stories: 000 module split; 001 DHT E1 (DidDht default removal + node DhtMode Memory->test-harness-only + fail-closed Disabled); 006 nullifier severance (custody/attestation/DHT) + delete switch + pre-rotation isolation + G1; 009 E2 credentials (delete impl Default live fix); 010 E3 blob (delete impl Default live fix); 011 E4 relay-publisher default sever (InMemoryRelayPublisher default removed + demoted to test-harness-only; NoOpRelayQuerier unchanged; relay resolution itself is #482). #1733 folds+closes at Slice 6 for custody/attestation/DHT/storage (pre-rotation row -> RFC #2130). Forward-only DAG.",
````

Live text after the cut:

````text
  "description": "Realization of ADR-062 (applying umbrella spec §17.17 unchanged), scoped to capabilities that have a real backend TODAY. Every in-memory NULLIFIER with a real backend (key custody -> File/Sqlite/callback; device attestation -> declined per spec §9:187; identity resolution -> Pkarr) becomes a test-harness-only double gated `#[cfg(feature = \"testing\")]`, provably absent from shipped artifacts via G1's SOLE closed subset-allowlist; durability-only arms (storage, push, blob) stay legitimate explicit runtime options, never Default. The allow_in_memory_custody switch, the public custody=in_memory config, and the DidDht<D=InMemoryDhtClient> nullifier-default type parameter are all deleted. E4 relay layer: NoOpRelayQuerier (READ) is NOT a nullifier — it fails CLOSED (Ok(None), never a false document) and ships honestly, UNCHANGED, as the DHT-only interim. Slice 11's ONLY scope is the E4 WRITE-path default-selection hygiene fix: sever the InMemoryRelayPublisher default type param on RepublishManager (republish.rs:397) + demote InMemoryRelayPublisher to #[cfg(any(test, feature=\"testing\"))], matching E1/E3. Building relay resolution itself — the real MultiRelayQuerier, a real RelayPublisher, the key-event-record frame (§9.10.12), relay-side validation, and the republish-loop signature/sequence-drop fix (republish.rs:703) — is issue #482 (a FEATURE; spec §3.10.2/§3.10.4/§3.10.8, §9.10.12), OUT of ADR-062 scope and storied under .docs/prds/relay-did-resolution.json. PRE-ROTATION CUSTODY IS OUT OF SCOPE: production realization is punted to a later e2e-collab stage (RFC #2130 / #1729 / #1777); ADR-054 is Proposed, only the §3a residence RULE is canonical (spec §9.7.4.1 item 3a). Because no real pre-rotation backend is built now, Slice 6 severs the InMemoryPreRotationCustody NULLIFIER to test-harness-only (#[cfg(feature=\"testing\")], folded into `testing` like custody/attestation — NO standalone allowlisted feature) and makes production identity creation FAIL CLOSED with a typed error rather than fall back to the nullifier. G1 allowlists durability-only + real-backend features — ZERO nullifiers, no exceptions (PR #2132). Only the real pre-rotation BACKEND is out of scope (RFC #2130 / #1729); whether identities may be created without a pre-rotation commitment is #1553. Five stories: 000 module split; 001 DHT E1 (DidDht default removal + node DhtMode Memory->test-harness-only + fail-closed Disabled); 006 nullifier severance (custody/attestation/DHT) + delete switch + pre-rotation isolation + G1; 010 E3 blob (delete impl Default live fix); 011 E4 relay-publisher default sever (InMemoryRelayPublisher default removed + demoted to test-harness-only; NoOpRelayQuerier unchanged; relay resolution itself is #482). #1733 folds+closes at Slice 6 for custody/attestation/DHT/storage (pre-rotation row -> RFC #2130). Forward-only DAG.",
````

## `.docs/prds/adr062-capability-injection.json`, the entry `gate-capinject-9`, lines 26–32 on main when archived

````text
    {
      "id": "gate-capinject-9",
      "name": "E2 credentials real backend + seam (Slice 9, Unit 3)",
      "stories": [
        "SCP-CAPINJECT-009"
      ]
    },
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/adr062-capability-injection.json`, the entry `SCP-CAPINJECT-009`, lines 328–381 on main when archived

````text
    {
      "id": "SCP-CAPINJECT-009",
      "title": "E2 credentials: delete the impl Default (live SCP-CAPSEL-8000/8011 fix), introduce the FfiCredentialStore enum seam + a real durable backend, demote InMemoryCredentialStore to test-harness-only",
      "gate": "gate-capinject-9",
      "priority": "P0",
      "severity": "critical",
      "status": "done",
      "files": [
        "crates/scp-runtime/src/bridge/credentials.rs",
        "crates/scp-ffi/common/src/credentials.rs",
        "crates/scp-ffi/common/src/lib.rs",
        "crates/scp-ffi/napi/src/runtime.rs",
        "crates/scp-ffi/src/runtime.rs",
        ".docs/standards/sdk-capability-matrix.json"
      ],
      "description": "ADR-062 Slice 9 (Unit 3, E2 HIGH; §Decision 5). The `impl Default for InMemoryCredentialStore` (credentials.rs:556) wired on shipped NAPI+PyO3 (napi/runtime.rs:313) is a LIVE SCP-CAPSEL-8000/8011 violation (a default selection) — its removal is not deferrable. `BridgeCredentialStore` is RPITIT -> introduce an `enum FfiCredentialStore { Durable(<real durable backend>), #[cfg(feature = \"testing\")] InMemory(InMemoryCredentialStore) }`, DELETE the `impl Default`, require an explicit selection at the bridge construction boundary, and ship a real durable credential store (persisted bridge tokens). InMemoryCredentialStore -> test-harness-only. Classified durability-only (RAM-only tokens are re-obtainable by re-auth); the selection-boundary fix is the security-relevant part. Add the credentials-backend row to the capability matrix. Independent of the DHT/pre-rotation work (blockedBy []); gate-sequenced after Unit 1/2 but the impl-Default removal is a live fix and can land as soon as scheduled. Scope exception: the seam + durable backend + Default removal are one selection-boundary change.",
      "acceptanceCriteria": [
        "The `impl Default` is deleted (live SCP-CAPSEL-8000/8011 fix): `grep -n 'impl Default for InMemoryCredentialStore\\|impl Default for BridgeCredentialStore' crates/scp-runtime/src/bridge/credentials.rs` returns 0.",
        "An `enum FfiCredentialStore` seam exists with a real Durable arm + a test-harness InMemory arm: `grep -n 'enum FfiCredentialStore' crates/scp-ffi/common/src/credentials.rs` matches with a `Durable` arm and an `InMemory` arm gated `#[cfg(feature = \"testing\")]`.",
        "The bridge requires an explicit credential-store selection (no default): outside `#[cfg(feature = \"testing\")]`, `grep -rn 'InMemoryCredentialStore' crates/scp-ffi/napi/src/runtime.rs crates/scp-ffi/src/runtime.rs` returns 0, and a real durable backend is selected at construction (grep the construction site).",
        "A real durable credential store persists tokens across restart: a test writes a bridge token, drops+reconstructs the store from the durable backend, and reads the token back (proving it is not RAM-only).",
        ".docs/standards/sdk-capability-matrix.json has a credentials-backend row; `python3.12 scripts/check-sdk-coverage.py` exits 0.",
        "Full CI green: `cargo fmt --all -- --check`; the workspace clippy command; `DYLD_LIBRARY_PATH=$(python3.12 -c \"import sysconfig; print(sysconfig.get_config_var('LIBDIR'))\") cargo test --workspace` — all exit 0.",
        "`python3.12 scripts/validate-prd.py` exits 0 with this story present."
      ],
      "actionItems": [
        "Delete the impl Default in credentials.rs; add the FfiCredentialStore enum seam (Durable + `#[cfg] InMemory`); require explicit selection at the bridge boundary.",
        "Implement a real durable credential store (persisted bridge tokens); demote InMemoryCredentialStore to test-harness-only.",
        "Add the credentials-backend row to the capability matrix; write the persistence + selection tests; run full CI + review roster."
      ],
      "blockedBy": [],
      "sources": [
        {
          "file": ".docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md",
          "section": "### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)"
        },
        {
          "file": ".docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md",
          "section": "## Capability classification (§17.17.2 SCP-CAPSEL-8010 — mandatory before ship)"
        },
        {
          "file": ".docs/specs/17-persistence-and-storage.md",
          "section": "### 17.17.2 Security Classification of Development Arms"
        }
      ],
      "details": {
        "phase": "2",
        "adr": "ADR-062",
        "unit": "3",
        "slice": "Slice 9 (E2 credentials)",
        "scopeException": "seam + durable backend + Default removal are one selection-boundary change",
        "verified_on_main": "Verified AC-by-AC against origin/main. AC[0]: `grep -c 'impl Default for InMemoryCredentialStore|impl Default for BridgeCredentialStore' crates/scp-runtime/src/bridge/credentials.rs` = 0. AC[1]: `pub enum FfiCredentialStore` at crates/scp-ffi/common/src/credentials.rs:45 with a `Durable(Arc<dyn DurableCredentialBackend>)` arm and an `InMemory` arm gated `#[cfg(feature = \"testing\")]`. AC[3]: `bridge_credential_survives_store_drop_and_reopen` (crates/scp-runtime/src/store/credentials.rs) opens a real on-disk SqliteStorage, writes the credential + root key, DROPS the store and its Arc, reopens at the same path/key, and asserts the ciphertext and root key are byte-identical — proving it is not RAM-only."
      }
    },
````

The cut deleted these lines and left no replacement text.

## `.docs/prds/adr062-capability-injection.json`, the entry `SCP-CAPINJECT-010`, line 410 on main when archived

````text
          "section": "### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)"
````

Live text after the cut:

````text
          "section": "### 5. Blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)"
````

## `.docs/prds/adr062-capability-injection.json`, the entry `SCP-CAPINJECT-011`, line 432 on main when archived

````text
      "title": "E4 relay-publisher default sever (WRITE-path default-selection hygiene ONLY): remove the InMemoryRelayPublisher default type param on RepublishManager (republish.rs:397), require an explicit publisher, and demote InMemoryRelayPublisher to #[cfg(any(test, feature=\"testing\"))] — matching E1/E2/E3. NoOpRelayQuerier ships unchanged; building relay resolution is issue #482, out of ADR-062 scope",
````

Live text after the cut:

````text
      "title": "E4 relay-publisher default sever (WRITE-path default-selection hygiene ONLY): remove the InMemoryRelayPublisher default type param on RepublishManager (republish.rs:397), require an explicit publisher, and demote InMemoryRelayPublisher to #[cfg(any(test, feature=\"testing\"))] — matching E1/E3. NoOpRelayQuerier ships unchanged; building relay resolution is issue #482, out of ADR-062 scope",
````

## `.docs/prds/adr062-capability-injection.json`, the entry `SCP-CAPINJECT-011`, line 461 on main when archived

````text
          "section": "### 5. Credentials (E2), blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)"
````

Live text after the cut:

````text
          "section": "### 5. Blob (E3), relay-publisher default (E4) — classified + storied now (live SCP-CAPSEL fixes)"
````

## `.docs/prds/capability-registry.json`, the top-level PRD fields, line 3 on main when archived

````text
  "description": "Agent Capability Registry: URI namespace for agent capabilities (ADR-041), unifying ChallengeType and CapabilityEntry under structured URIs. Three authorities: scp:capability:* (protocol-defined, reserved), {identifier}:capability:* (identity-scoped custom), scp:system:* (protocol feature flags). 28 challenge capabilities + 5 system capabilities. SDK validation rejects unknown protocol-scoped URIs. Context admission requirements reference capability URIs with verification levels.",
````

Live text after the cut:

````text
  "description": "Agent Capability Registry: URI namespace for agent capabilities (ADR-041), unifying ChallengeType and CapabilityEntry under structured URIs. Three authorities: scp:capability:* (protocol-defined, reserved), {identifier}:capability:* (identity-scoped custom), scp:system:* (protocol feature flags). 28 challenge capabilities + 4 system capabilities. SDK validation rejects unknown protocol-scoped URIs. Context admission requirements reference capability URIs with verification levels.",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-002`, line 106 on main when archived

````text
      "title": "Implement protocol capability registry with 28 challenge + 5 system capabilities",
````

Live text after the cut:

````text
      "title": "Implement protocol capability registry with 28 challenge + 4 system capabilities",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-002`, line 115 on main when archived

````text
      "description": "Implement the protocol capability registry per ADR-041 and §7.3.4.3. The registry is a compile-time constant map from CapabilityUri to RegistryEntry containing category, description, and optional parameter schema (serde_json::Value). The registry contains 28 challenge capabilities across 10 categories and 5 system capabilities. Provides lookup_protocol_capability(uri) -> Option<&RegistryEntry> and is_known_protocol_capability(uri) -> bool. The validate_capability_uri(uri) function rejects unknown scp:capability:* URIs while accepting all valid identity-scoped URIs. This is the SDK enforcement point described in §7.3.4.2.",
````

Live text after the cut:

````text
      "description": "Implement the protocol capability registry per ADR-041 and §7.3.4.3. The registry is a compile-time constant map from CapabilityUri to RegistryEntry containing category, description, and optional parameter schema (serde_json::Value). The registry contains 28 challenge capabilities across 10 categories and 4 system capabilities. Provides lookup_protocol_capability(uri) -> Option<&RegistryEntry> and is_known_protocol_capability(uri) -> bool. The validate_capability_uri(uri) function rejects unknown scp:capability:* URIs while accepting all valid identity-scoped URIs. This is the SDK enforcement point described in §7.3.4.2.",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-002`, line 119 on main when archived

````text
        "SYSTEM_REGISTRY contains exactly 5 entries with CapabilityUri::System variants",
````

Live text after the cut:

````text
        "SYSTEM_REGISTRY contains exactly 4 entries with CapabilityUri::System variants",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-002`, line 127 on main when archived

````text
        "validate_capability_uri accepts all 5 system capabilities",
````

Live text after the cut:

````text
        "validate_capability_uri accepts all 4 system capabilities",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-002`, line 135 on main when archived

````text
        "Build SYSTEM_REGISTRY with all 5 entries",
````

Live text after the cut:

````text
        "Build SYSTEM_REGISTRY with all 4 entries",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-006`, line 305 on main when archived

````text
      "description": "Extend the service record's capability advertising to support system capabilities (scp:system:*). System capabilities use the same SCPCapabilities service endpoint format as challenge capabilities but with the scp:system: prefix. The parse_capability_endpoint function already handles this via the CapabilityUri parser (SCP-ACR-005), but this story ensures system capabilities are properly represented, documented, and tested. System capabilities describe node roles (relay-operation, bridge-operation, etc.) and are not subject to challenge-response verification. Contexts and peers discover system capabilities by resolving the service record.",
````

Live text after the cut:

````text
      "description": "Extend the service record's capability advertising to support system capabilities (scp:system:*). System capabilities use the same SCPCapabilities service endpoint format as challenge capabilities but with the scp:system: prefix. The parse_capability_endpoint function already handles this via the CapabilityUri parser (SCP-ACR-005), but this story ensures system capabilities are properly represented, documented, and tested. System capabilities describe node roles (relay-operation, etc.) and are not subject to challenge-response verification. Contexts and peers discover system capabilities by resolving the service record.",
````

## `.docs/prds/capability-registry.json`, the entry `SCP-ACR-006`, line 307 on main when archived

````text
        "parse_capability_endpoint('scp:capabilities:scp:system:relay-operation,scp:system:bridge-operation') returns two valid CapabilityUri::System entries",
````

Live text after the cut:

````text
        "parse_capability_endpoint('scp:capabilities:scp:system:relay-operation') returns one valid CapabilityUri::System entry",
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-005`, line 228 on main when archived

````text
      "title": "Release the NAT mapping on shutdown and keep dev/bridge endpoints loopback-only",
````

Live text after the cut:

````text
      "title": "Release the NAT mapping on shutdown and keep dev endpoints loopback-only",
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-005`, line 237 on main when archived

````text
      "description": "Self-host mode opens an inbound NAT port mapping (§10.12.2). On clean shutdown the mapping MUST be released so the operator's router does not retain a stale public forward after the process exits (`release_self_host_mappings` in `crates/scp-node/src/main.rs` removes the mapping on each mapper); when no mapper is present (the non-`upnp` build) the release is a safe no-op. Separately, the node's dev/control and bridge endpoints MUST NOT be exposed to the public internet by self-host mode: the dev API restricts itself to loopback hosts (`dev_api::ALLOWED_HOSTS = [\"localhost\", \"127.0.0.1\", \"[::1]\"]`), and the self-host public surface (§10.12.11 'Origin-root mount') never mounts the relay upgrade (`/scp/v1`) or bridge routes (`/v1/scp/bridge/*`). This is the teardown + endpoint-exposure hardening story.",
````

Live text after the cut:

````text
      "description": "Self-host mode opens an inbound NAT port mapping (§10.12.2). On clean shutdown the mapping MUST be released so the operator's router does not retain a stale public forward after the process exits (`release_self_host_mappings` in `crates/scp-node/src/main.rs` removes the mapping on each mapper); when no mapper is present (the non-`upnp` build) the release is a safe no-op. Separately, the node's dev/control endpoints MUST NOT be exposed to the public internet by self-host mode: the dev API restricts itself to loopback hosts (`dev_api::ALLOWED_HOSTS = [\"localhost\", \"127.0.0.1\", \"[::1]\"]`), and the self-host public surface (§10.12.11 'Origin-root mount') never mounts the relay upgrade (`/scp/v1`). This is the teardown + endpoint-exposure hardening story.",
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-005`, line 242 on main when archived

````text
        "Self-host mode does NOT expose the relay/bridge endpoints on the public surface: test `self_host_public_surface_excludes_relay_and_bridge` asserts over a real bound listener that the site route serves while `/scp/v1` and `/v1/scp/bridge/*` are NOT routed (fall through to 404)"
````

Live text after the cut:

````text
        "Self-host mode does NOT expose the relay endpoint on the public surface: test `self_host_public_surface_excludes_relay` asserts over a real bound listener that the site route serves while `/scp/v1` is NOT routed (fall through to 404)"
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-005`, lines 248–249 on main when archived

````text
        "Ensure the self-host public surface does not mount the relay upgrade or bridge routes",
        "Add tests: release_self_host_mappings_removes_mapping_on_both_mappers, release_self_host_mappings_noop_when_no_mappers, self_host_public_surface_excludes_relay_and_bridge"
````

Live text after the cut:

````text
        "Ensure the self-host public surface does not mount the relay upgrade",
        "Add tests: release_self_host_mappings_removes_mapping_on_both_mappers, release_self_host_mappings_noop_when_no_mappers, self_host_public_surface_excludes_relay"
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-007`, line 364 on main when archived

````text
      "description": "§10.17 defines two participant deployment shapes; SHB-002 ships the BUNDLED (co-located) shape. This story ENABLES/VERIFIES the EXTERNAL shape with ZERO new node API: an SDK participant client in a separate process reaches this node's relay over the EXISTING controls — the node's TLS-terminated `PublicSurface::Full` public surface (§10.12.11), the bind address, and the `TlsMode` (§10.12.6: loopback ws:// same-box, wss:// off-host) — exactly as for any client of the relay's `/scp/v1` route. There is NO dedicated listener toggle, admission token, or pre-shared secret: relays are anonymous, DHT-auto-discovered dumb pipes that participants do not hand-pick, so an admission/allowlist token is at odds with the relay model (§10.4). Abuse prevention for an open wss:// relay is provided by the relay's EXISTING rate limiting and abuse controls (§10.4 — `PublishRateLimiter` + `ConnectionTracker` + the `/scp/v1` semaphore) together with relay economics (§19.8 Relay Monetization, including `rate_limit_publish`), which together satisfy §10.4's 'rate limiting and abuse prevention' requirement. Access control for an external participant remains CRYPTOGRAPHIC, not transport-level: the relay is a protocol-unaware dumb pipe (§10.4) and the participant's authority to read or write context content is enforced by MLS group membership + UCAN (encryption-as-access-control) — a non-member connecting to `/scp/v1` sees only ciphertext. This story MUST NOT weaken SHB-005: dev/control (dev_api ALLOWED_HOSTS loopback-only) and bridge routes (`/v1/scp/bridge/*`) stay loopback-only and are never mounted on a public surface.",
````

Live text after the cut:

````text
      "description": "§10.17 defines two participant deployment shapes; SHB-002 ships the BUNDLED (co-located) shape. This story ENABLES/VERIFIES the EXTERNAL shape with ZERO new node API: an SDK participant client in a separate process reaches this node's relay over the EXISTING controls — the node's TLS-terminated `PublicSurface::Full` public surface (§10.12.11), the bind address, and the `TlsMode` (§10.12.6: loopback ws:// same-box, wss:// off-host) — exactly as for any client of the relay's `/scp/v1` route. There is NO dedicated listener toggle, admission token, or pre-shared secret: relays are anonymous, DHT-auto-discovered dumb pipes that participants do not hand-pick, so an admission/allowlist token is at odds with the relay model (§10.4). Abuse prevention for an open wss:// relay is provided by the relay's EXISTING rate limiting and abuse controls (§10.4 — `PublishRateLimiter` + `ConnectionTracker` + the `/scp/v1` semaphore) together with relay economics (§19.8 Relay Monetization, including `rate_limit_publish`), which together satisfy §10.4's 'rate limiting and abuse prevention' requirement. Access control for an external participant remains CRYPTOGRAPHIC, not transport-level: the relay is a protocol-unaware dumb pipe (§10.4) and the participant's authority to read or write context content is enforced by MLS group membership + UCAN (encryption-as-access-control) — a non-member connecting to `/scp/v1` sees only ciphertext. This story MUST NOT weaken SHB-005: dev/control (dev_api ALLOWED_HOSTS loopback-only) stays loopback-only and is never mounted on a public surface.",
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-007`, line 367 on main when archived

````text
        "SHB-005 isolation holds: test `self_host_public_surface_excludes_relay_and_bridge` still passes, proving the read-only self-host (`PublicSurface::SelfHost`) public surface never mounts `/scp/v1` or `/v1/scp/bridge/*`, and CI command `grep -q 'ALLOWED_HOSTS' crates/scp-node/src/dev_api.rs` returns true (loopback-only dev host allowlist unchanged)"
````

Live text after the cut:

````text
        "SHB-005 isolation holds: test `self_host_public_surface_excludes_relay` still passes, proving the read-only self-host (`PublicSurface::SelfHost`) public surface never mounts `/scp/v1`, and CI command `grep -q 'ALLOWED_HOSTS' crates/scp-node/src/dev_api.rs` returns true (loopback-only dev host allowlist unchanged)"
````

## `.docs/prds/self-host-binary.json`, the entry `SHB-007`, line 373 on main when archived

````text
        "Keep dev/control (ALLOWED_HOSTS loopback-only) and bridge routes unmounted on any public surface (do not regress SHB-005); keep `self_host_public_surface_excludes_relay_and_bridge` passing"
````

Live text after the cut:

````text
        "Keep dev/control (ALLOWED_HOSTS loopback-only) unmounted on any public surface (do not regress SHB-005); keep `self_host_public_surface_excludes_relay` passing"
````

## `.docs/sketch.md`, under `### Identity Attestations (§3.5)`, line 67 on main when archived

````text
Cryptographic proofs binding external platform identities to your identifier. Makes bridging trustworthy and social graph import possible.
````

Live text after the cut:

````text
Cryptographic proofs binding external platform identities to your identifier. Makes social graph import possible.
````

## `.docs/sketch.md`, under `### Inspect (before opt-in)`, line 320 on main when archived

````text
  bridges: [BridgeInfo]?,         // active bridge connectors, if any
````

The cut deleted these lines and left no replacement text.

## `.docs/sketch.md`, under `### Propose Change`, lines 911–912 on main when archived

````text
        | .addBridge(BridgeDefinition)
        | .removeBridge(bridgeID)
````

The cut deleted these lines and left no replacement text.

## `.docs/sketch.md`, under `## 7. Bridge Connectors (§12)`, lines 931–992 on main when archived

````text
## 7. Bridge Connectors (§12)

### Register Bridge

Bring external platform participants into an SCP context.

```
SCP.Bridge.register(
  context: contextID,
  operator: Identifier,                   // accountable identity running the bridge
  platform: "x" | "facebook" | "whatsapp" | "discord" | ...,
  mode: .relay | .puppet | .api | .cooperative
) → BridgeInstance { bridgeID, contextID, operator, platform, mode }
```

### Shadow Identities

External platform users represented in SCP contexts.

```
// Bridge creates a shadow identity for an external user
SCP.Bridge.createShadow(
  bridge: bridgeID,
  externalIdentity: { platform: "x", handle: "@dave" },
  attributedBy: bridgeOperatorIdentifier
) → ShadowIdentity {
  shadowID, platform, handle, bridgeID,
  role: "observer",               // restricted by default
  provenance: .bridged(mode, operator)
}

// External user later claims their shadow with an identity attestation
SCP.Bridge.claimShadow(
  shadowID: shadowID,
  claimant: Identifier,
  attestation: Attestation        // identity_link matching the shadow's platform handle
) → Result<ShadowClaimEvent, ClaimError>
// On success: shadow retired, history attributed to the claimant's identifier
// On error: ClaimError (HandleMismatch, AttestationInvalid, AlreadyClaimed, ShadowNotFound)
```

### Bridge Content Provenance

All bridged content carries provenance automatically.

```
// Bridged message carries:
BridgedMessage {
  content: ...,
  provenance: {
    source: .bridge(bridgeID),
    platform: "x",
    operator: Identifier,
    mode: .relay,
    attribution: .shadow(shadowID) | .claimed(Identifier),
    trustLevel: .native | .nativeBridged | .claimedShadow | .unclaimedShadow
  }
}
```

---

````

The cut deleted these lines and left no replacement text.

## `.docs/sketch.md`, under `### Bridging: X Users Participate in a Quest Community`, lines 1179–1206 on main when archived

````text
### Bridging: X Users Participate in a Quest Community

```swift
// 1. Alice registers an X bridge in her quest context
let bridge = try await SCP.Bridge.register(
  context: quest.contextID,
  operator: alice.identifier,           // Alice runs the bridge
  platform: "x",
  mode: .relay
)

// 2. Bridge creates shadow identities for X participants
let daveShadow = try await SCP.Bridge.createShadow(
  bridge: bridge.bridgeID,
  externalIdentity: { platform: "x", handle: "@dave_cooks" },
  attributedBy: alice.identifier
)
// Dave appears in context as observer, bridged provenance

// 3. Dave later joins SCP and claims his shadow
let claimResult = try await SCP.Bridge.claimShadow(
  shadowID: daveShadow.shadowID,
  claimant: dave.identifier,
  attestation: daveXAttestation  // proves @dave_cooks is dave.identifier
)
// Shadow retired. Dave's historical bridged messages now attributed to his identifier.
```

````

The cut deleted these lines and left no replacement text.

## `.docs/sketch.md`, under `### Context Metadata Response`, lines 1419–1421 on main when archived

````text
  "bridges": [
    { "platform": "x", "mode": "relay", "operator": "<scp-identifier:operator>", "shadows": 12 }
  ],
````

The cut deleted these lines and left no replacement text.
