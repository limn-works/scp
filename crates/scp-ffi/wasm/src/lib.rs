// wasm-bindgen does not support `const fn` on exported methods, so we suppress
// the lint crate-wide. Similarly, wasm-bindgen requires owned `String` for
// function parameters (not `&str`), making `needless_pass_by_value` a false
// positive on all `#[wasm_bindgen]` bridge functions.
#![allow(clippy::missing_const_for_fn, clippy::needless_pass_by_value)]

//! `wasm-bindgen` FFI bridge for SCP — the browser-target Rust half of the
//! TypeScript SDK.
//!
//! This crate is compiled to WebAssembly via `wasm-pack` and consumed by the
//! `@limn-works/scp-ts` npm package. It exposes a flat set of `#[wasm_bindgen]` types
//! and functions that map directly to `scp-core`'s public API surface.
//!
//! # Architecture
//!
//! The bridge is organized into domain modules that mirror the `PyO3` bridge
//! (`crates/scp-ffi/src/`) at the same logical API surface:
//!
//! - [`error`] — Rust `Result` → JS typed exception mapping.
//! - [`identity`] — Identity lifecycle (`identity_create`, `identity_load`,
//!   `identity_resolve`).
//! - [`context`] — Context lifecycle (create, join, leave, close, send,
//!   subscribe).
//! - [`tools`] — Tool registration, invocation, and verification.
//! - [`transport`] — Transport connection and status.
//! - [`ucan`] — UCAN token management (validate, mint, revoke).
//! - [`event_log`] — Event log queries and Merkle proofs.
//! - [`runtime`] — WASM-local runtime registry (tool registry, event log,
//!   UCAN revocation, schema validation).
//! - [`custody`] — JS-injected key custody callback types (`WebCrypto`).
//! - [`storage`] — JS-injected storage callback types (OPFS/`IndexedDB`).
//!
//! # Async model
//!
//! WASM in browsers runs on a single thread without Tokio. All async bridge
//! functions use [`wasm_bindgen_futures::future_to_promise`] to return
//! `Promise<T>` to JavaScript. Futures must be non-blocking (no blocking
//! I/O inside futures).
//!
//! # WASM constraints and scp-core
//!
//! `scp-core` depends on `tokio = { features = ["full"] }` which includes the
//! multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile
//! tokio's multi-thread runtime. Therefore, this bridge does NOT directly
//! depend on `scp-core`. Instead:
//!
//! 1. Opaque JS handle types ([`identity::WasmIdentity`], `WasmContextHandle`, etc.)
//!    establish the stable ABI boundary.
//! 2. Bridge stub functions return typed errors documenting the JS-side
//!    implementation pattern (`WebCrypto`, Fetch API, WebSocket).
//! 3. JS callback injection types ([`custody::JsKeyCustody`], [`storage::JsStorage`],
//!    `JsMessageCallback`) define the TypeScript wrapper's responsibility.
//!
//! The JS callback injection pattern is the permanent WASM architecture per
//! ADR-022: browser-native APIs (`WebCrypto`, OPFS, WebSocket) are injected from
//! the TypeScript wrapper layer. The napi-rs bridge (`crates/scp-ffi/napi/`)
//! is the path that depends on `scp-core` directly, serving Node.js/Bun.
//!
//! # JS callback injection
//!
//! Browser-native APIs (`WebCrypto`, wa-sqlite / OPFS, `IndexedDB`) are not
//! available as Rust crates — they are JavaScript APIs. The bridge exposes
//! extern `JsKeyCustody` and `JsStorage` types so the TypeScript wrapper can
//! inject implementations.
//!
//! # Error mapping
//!
//! Rust `Result<T, ScpWasmError>` maps to JS `Promise` rejection via
//! [`wasm_bindgen::JsError`]. Each error variant carries a stable error code
//! string (`[SCP-IDENT-1000]` through `[SCP-VALID-7000]`) for programmatic
//! handling in TypeScript.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` for the full specification.

/// Bridge connector operations (registration, trust evaluation, shadow identities).
pub mod bridge;
/// Consequence rule evaluation and enforcement (ADR-017, #1531).
///
/// Wraps `scp_protocol::trust::consequence::evaluate_consequence_rules`
/// with WASM-local state mutation so that rules declared at context creation
/// are enforced inside [`crate::manager::PerContextState`]. See the module
/// docs for dispatch call sites.
pub(crate) mod consequence;
/// Context lifecycle and messaging (create, join, leave, close, send, subscribe).
pub mod context;
/// MLS encryption and sender key layer for real message confidentiality.
pub mod crypto;
/// JS-injected key custody callback types (`WebCrypto` integration).
pub mod custody;
/// Context discovery operations.
pub mod discovery;
/// Economic governance operations (cost estimation, budget, antispam, pricing).
pub mod economy;
/// Error hierarchy and `ScpWasmError` to `JsError` mapping.
pub mod error;
/// Event log queries, Merkle proofs, and consistency checkpoints.
pub mod event_log;
/// Identity lifecycle (create, load, resolve, agent key management).
pub mod identity;
/// Centralized context state manager (`WasmContextManager`).
pub mod manager;
/// Provenance metadata operations.
pub mod provenance;
/// Reference attestation verification via browser Fetch API (§3.5.2).
pub mod reference_verify;
/// WASM-local runtime registry (tool registry, event log, schema validation).
pub mod runtime;
/// SCPID authentication — challenge generation and signing (§3.11).
pub mod scpid;
/// JS-injected storage callback types (OPFS / `IndexedDB` integration).
pub mod storage;
/// State synchronization operations.
pub mod sync;
/// Platform-agnostic time utilities for WASM.
pub mod time;
/// Tool registration, invocation, and verification.
pub mod tools;
/// Transport connection and status operations.
pub mod transport;
/// Trust engine operations (attestation, challenge, verification).
pub mod trust;
/// UCAN token management (validate, mint, revoke, delegate).
pub mod ucan;

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Module entry point
// ---------------------------------------------------------------------------

/// Initializes the WASM bridge.
///
/// Must be called once after the WASM module is loaded. Sets up the panic
/// hook so that Rust panics surface as readable browser console errors rather
/// than opaque WebAssembly traps.
///
/// This function is idempotent — calling it more than once is safe (the panic
/// hook is replaced with the same implementation).
///
/// # JS usage
///
/// ```js
/// import init, { scp_init } from '@limn-works/scp-ts-wasm';
/// await init();
/// scp_init();
/// ```
#[wasm_bindgen]
pub fn scp_init() {
    // Route Rust panics to the browser console as readable error messages.
    // std::panic::set_hook replaces any previously installed hook, so this
    // is idempotent in the sense that calling it again simply replaces the
    // hook with an identical implementation.
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        web_sys::console::error_1(&JsValue::from_str(&msg));
    }));
}

/// Returns the version string for the `scp-ffi-wasm` crate.
///
/// # JS usage
///
/// ```js
/// import { scp_version } from '@limn-works/scp-ts-wasm';
/// console.log(scp_version()); // "0.1.0"
/// ```
#[must_use]
#[wasm_bindgen]
pub fn scp_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
