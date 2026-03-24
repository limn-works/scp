# scp-ffi-wasm — wasm-bindgen Bridge Layer

## Overview

This crate is the browser-target Rust half of the `@limn-works/scp-ts` TypeScript package. It exposes SCP protocol operations to JavaScript via `wasm-bindgen`, compiled to WebAssembly with `wasm-pack`. See ADR-022 in `.docs/adrs/phase-4.md`.

## Architecture Constraint: No scp-runtime Dependency

`scp-runtime` depends on `tokio = { features = ["full"] }` which requires a multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile this. Therefore, **this crate does NOT depend on scp-runtime**. WASM imports pure sync types from `scp-protocol` and event log types from `scp-event-log`. Only WASM-specific orchestration and JS bridge logic remains local.

## What Was Migrated (from scp-protocol / scp-event-log)

The following modules previously contained standalone WASM reimplementations. After the scp-protocol migration, they import shared types and algorithms directly:

| Area | Import Source | What |
|------|-------------|------|
| Sender key | `scp_protocol::crypto::sender_keys` | `SenderKey`, `generate_sender_key`, `encrypt_sender_layer`, `decrypt_sender_layer`, `SenderKeyError` |
| UCAN | `scp_protocol::crypto::ucan` | `CapabilityUri`, `UcanToken`, `UcanError`, `validate_ucan`, `parse_ucan`, `compute_revocation_cid`, `default_ceiling` |
| UCAN validation traits | `scp_protocol::crypto::ucan::validate` | `DidResolver`, `InMemoryProofResolver`, `InMemoryRevocationChecker`, `ValidationNonceTracker`, `ValidationContext` |
| Event log | `scp_event_log` | `EventLog`, `Event`, `EventPayload`, `EventType`, `DID`, `proof::*`, `tree::*` |
| Tool types | `scp_protocol::context::tools::schema` | `ToolRegistration`, `ToolCost`, `ToolSchema`, `validate_schema`, `validate_value_against_schema` |
| Trust | `scp_protocol::trust::participation` | `ParticipationProfile`, `RequireParticipation` |
| Provenance | `scp_protocol::provenance` | `SourceType`, `DEFAULT_MAX_CHAIN_DEPTH` |
| Bridge | `scp_protocol::bridge` | `BridgeMode`, `ShadowProvenanceStatus` |
| Identity | `scp_protocol::trust::attestation` | `RevocationStatus` |
| Discovery | `scp_protocol::discovery::petnames` | `PetnameMap`, `PetnameEvent` |
| Context | `scp_protocol::context::params` | `TemplateId` |
| Context templates | `scp_protocol::context::templates` | `template_params`, `ContentPath`, `MimeType`, `BroadcastContent`, `serialize_broadcast_content` |
| Sync | `scp_protocol::sync` | `SyncPolicy`, `OfflineTier` |
| Economy | `scp_protocol::economy` | `evaluate_formula`, `PricingFormula`, `ObservableMetrics` |
| SCPID | `scp_protocol::identity::scpid` + `scp_protocol::crypto::canonical` | `ScpIdChallenge`, `ScpIdResponse`, `SCPID_PROTOCOL_VERSION`, `SCPID_DOMAIN_SEPARATOR`, `canonical_hash`, `CanonicalField` |

## What Stays WASM-Local (and why)

| Module / Area | Why it remains local |
|--------------|---------------------|
| MLS orchestration (`crypto/group.rs`, `crypto/encrypt.rs`, `crypto/state.rs`) | OpenMLS with `features = ["js"]` (WASM crypto backend). Same `openmls` crate as scp-core but different provider. |
| `wasm_bindgen` exports and JS bridge functions | All `#[wasm_bindgen]` entry points with JS-specific serialization |
| `time.rs` hardened clock | `js_sys::Date::now()` with negative-value clamping (ADR-034) |
| `WasmContextManager` state management (`manager.rs`) | `thread_local` `RefCell`, single-threaded — no `Mutex`/`DashMap` |
| `custody.rs` / `storage.rs` JS callback injection | ADR-022: WebCrypto and OPFS/IndexedDB injection points |
| `WasmCryptoState` | MLS + sender key orchestration (double encryption) |
| Governance dispatch methods (`manager.rs`) | DID↔String conversion at protocol boundary, JSON serialization of typed params |
| Address parsing in `discovery.rs` | Interleaved with WASM-specific JS-facing logic |
| `scpid.rs` bridge glue | `#[wasm_bindgen]` functions, JS error mapping, WASM time/CSPRNG. Types and constants imported from `scp_protocol::identity::scpid`. |
| `reference_verify.rs` | Uses browser Fetch API |
| `WasmNonceTracker` in `ucan.rs` | Implements `ValidationNonceTracker` trait with extract-validate-writeback pattern for `WasmContextManager` |
| Provenance hashing (`provenance.rs`) | WASM-local canonical byte construction (`CanonicalProvenance`) |
| Attestation canonical bytes | WASM-local canonical signing byte construction |
| Role capability checking (`manager.rs`) | `member_has_capability` with WASM-local ceiling intersection |
| Governance proposal lifecycle (`manager.rs`) | `GovernanceProposal` (from scp-protocol), resolved proposal eviction, proposal JSON serialization |

## Module Structure

| Module | Responsibility | Dependency Source |
|--------|---------------|-------------------|
| `runtime.rs` | Runtime helpers: re-exports `ToolRegistry` from scp-protocol, `tool_registry_insert_unique` wrapper, hex helpers | `scp_protocol::context::tools` |
| `manager.rs` | `WasmContextManager`: context lifecycle, governance, broadcast, role checking, event log (via `scp_event_log::EventLog`) | Local + `scp_event_log` + `scp_protocol::context::broadcast_content` |
| `context.rs` | Context lifecycle: create, join, leave, close, send, subscribe, export, import | Local + `scp_protocol::context::templates` |
| `tools.rs` | Tool registration, invocation, verification | Local + `scp_protocol::context::tools` |
| `ucan.rs` | UCAN token management: validate (delegates to `scp_protocol::crypto::ucan::validate::validate_ucan`), mint, revoke | `scp_protocol::crypto::ucan` |
| `event_log.rs` | Event log query, Merkle inclusion/absence proofs | `scp_event_log` |
| `identity.rs` | Identity create, load, resolve | Local + `scp_protocol::trust::attestation::RevocationStatus` |
| `transport.rs` | Transport connect/disconnect/status | Local |
| `custody.rs` | `JsKeyCustody` extern type (WebCrypto injection point) | Local |
| `storage.rs` | `JsStorage` extern type (OPFS/IndexedDB injection point) | Local |
| `error.rs` | `ScpWasmError` -> `JsError` mapping with stable error codes | Local |
| `crypto/sender_key.rs` | Re-exports from `scp_protocol::crypto::sender_keys` + error adapter | `scp_protocol` |
| `crypto/group.rs` | `WasmMlsGroup` — OpenMLS wrapper | Local (OpenMLS `js` feature) |
| `crypto/encrypt.rs` | Higher-level MLS encrypt/decrypt | Local |
| `crypto/state.rs` | `WasmCryptoState` — double encryption orchestration | Local |
| `crypto/credential.rs` | `WasmScpCredential` — MLS identity payload | Local |
| `crypto/error.rs` | `WasmCryptoError` enum | Local |
| `discovery.rs` | Discovery: address parsing, petname management | Local + `scp_protocol::discovery::petnames` |
| `trust.rs` | Trust participation profiles | Local + `scp_protocol::trust::participation` |
| `provenance.rs` | Provenance evaluation and attachment | Local + `scp_protocol::provenance::SourceType` |
| `bridge.rs` | Bridge mode and shadow provenance | Local + `scp_protocol::bridge` |
| `sync.rs` | Sync policy classification | Local + `scp_protocol::sync` |
| `economy.rs` | Economy formula evaluation | Local + `scp_protocol::economy` |
| `scpid.rs` | SCPID stateless DID auth | `scp_protocol::identity::scpid` + `scp_protocol::crypto::canonical` |

## MLS Encryption (`crypto/` module)

Real MLS encryption using OpenMLS 0.8 with `features = ["js"]`. **Not a reimplementation** — uses the same `openmls` crate as scp-core, just with the WASM-compatible JS crypto backend instead of `libcrux-provider`.

**Key design points:**
- `PerContextState` in `manager.rs` has a `crypto: Option<WasmCryptoState>` field. `Some` for encrypted contexts, `None` for broadcast/unencrypted.
- `create_context` auto-initializes crypto for Encrypted mode contexts.
- `send_message` encrypts via double layer when crypto is present.
- `join_context_encrypted` requires a prior `generate_key_package_for_join` call (two-step flow: generate KP -> send to adder -> receive Welcome -> join).
- `close_context` and `leave_context` destroy crypto state (zeroize keys).
- `WasmContextManager.pending_key_packages` stores key package holders between generate and join steps.
- `crypto/sender_key.rs` re-exports from `scp_protocol::crypto::sender_keys` (shared implementation, not a reimplementation).

**Ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (same as scp-core).

## UCAN — Shared Validation Pipeline

`ucan_validate` delegates to `scp_protocol::crypto::ucan::validate::validate_ucan` using an extract-validate-writeback pattern:

1. **EXTRACT** — Pull state from `WasmContextManager` (ceiling, revocation CIDs, seen nonces, creator DID).
2. **BUILD** — Create trait impls (`WasmDidResolver`, `WasmNonceTracker`, `InMemoryRevocationChecker`, `InMemoryProofResolver`).
3. **VALIDATE** — Call `validate_ucan` with the assembled `ValidationContext`.
4. **WRITEBACK** — Record the validated nonce in the manager.

`ucan_mint` generates Ed25519 keypair via `rand_core::OsRng`, builds and signs JWT, returns `WasmUcanToken` with `encoded` field.

`ucan_revoke` uses `scp_protocol::crypto::ucan::revoke::compute_revocation_cid` (shared implementation) and adds to both per-context UCAN state and runtime revocation set.

`default_ceiling` is imported from `scp_protocol::context::roles::default_ceiling`.

## Runtime Registry

WASM is single-threaded. The context registry uses `thread_local! { static CONTEXT_REGISTRY: RefCell<HashMap<String, WasmContextRuntime>> }` — no `Mutex` or `DashMap` needed. `with_context(id, closure)` is the access pattern, mirroring the PyO3 bridge's pattern.

`WasmContextRuntime` fields:
- `tool_registry: ToolRegistry` — tool registration/invocation
- `event_log: EventLog` — from `scp_event_log` (shared implementation)
- `revoked_tokens: HashSet<String>` — UCAN revocation set (CIDs)
- `ceiling_strings: HashSet<String>` — capability ceiling for UCAN validation
- `creator_did: String` — DID of the context creator

## Event Log — Shared Implementation

The event log uses `scp_event_log::EventLog` directly (no WASM reimplementation). Merkle proofs use `scp_event_log::proof::{prove_inclusion, prove_absence, verify_inclusion}`. Tree operations use `scp_event_log::tree::{append_unsigned_event, event_count, root}`. Each `PerContextState` owns an `EventLog` instance keyed by context ID.

## Identity — WASM-Local Registry

`identity_create` generates Ed25519 keypair via `rand_core::OsRng` (backed by `getrandom/js` -> `crypto.getRandomValues`), derives `did:dht:z{zbase32(pubkey)}`, and stores in `thread_local! IDENTITY_REGISTRY`. `identity_resolve` returns a DID document with the Ed25519 verification method for locally-created identities, or a minimal document for unknown DIDs.

The `zbase32_encode` function exists in both `identity.rs` and `ucan.rs` (duplicated to avoid coupling). If a third module needs it, extract to a shared `encoding.rs` module.

## Build

```sh
wasm-pack build crates/scp-ffi/wasm --target bundler
```

Produces `pkg/scp_ffi_wasm.js` + `pkg/scp_ffi_wasm_bg.wasm` consumed by the TypeScript wrapper.

For type-checking without a full wasm-pack build:
```sh
cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm
```

## Gotchas

- `wasm-bindgen` requires owned `String` parameters (not `&str`) for `#[wasm_bindgen]` functions — `clippy::needless_pass_by_value` is suppressed crate-wide.
- `wasm-bindgen` does not support `const fn` on exported methods — `clippy::missing_const_for_fn` is suppressed crate-wide.
- All async bridge functions use `wasm_bindgen_futures::future_to_promise` — futures must be non-blocking (no blocking I/O inside futures).
- `uuid::Uuid::new_v4()` requires the `getrandom/js` feature to use `crypto.getRandomValues` in the browser. Verify this is present in `Cargo.toml` when adding UUID usage.
- `js_sys::Date::now()` returns milliseconds since epoch as `f64` — divide by 1000.0 for seconds. Do not use `std::time::SystemTime` (not available on wasm32).
- `rand_core = { version = "0.6", features = ["getrandom"] }` provides `OsRng` for Ed25519 key generation. Works via `getrandom` 0.2 with `js` feature -> `crypto.getRandomValues`. Must match `ed25519-dalek`'s `rand_core` 0.6 version.
- `zbase32_encode` is duplicated in `identity.rs` and `ucan.rs`. Extract to shared module if a third consumer appears.
- Context close must clean up `CONTEXT_REGISTRY` in `runtime.rs`. Call `remove_context(context_id)` to release the `WasmContextRuntime` entry.
