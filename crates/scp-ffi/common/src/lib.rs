//! Shared types for SCP FFI bridges.
//!
//! Three module groups:
//!
//! - **`validate`** — Input validation (always available, no external deps).
//!   Used by all bridges (`PyO3`, napi-rs, `UniFFI`, WASM).
//!
//! - **`petname_helpers`** (behind `resolvers` feature) — Shared petname/handle/
//!   address-resolution helpers: JSON serialization, `HandleTarget` parsing,
//!   `HandleEntry` conversion, `HandleQuerier` impl, global singletons.
//!   Not available for WASM (ADR-034).
//!
//! - **Resolver adapters** (behind `resolvers` feature) — Bridge `scp-core`'s
//!   validation traits to the FFI runtime. Requires scp-core, scp-identity,
//!   tokio. Not available for WASM (ADR-034).
//!
//! See §3.10.10, §9.5, §7.4.1, §22.3.1, §22.4, §22.8 in `.docs/specs/`.

pub mod bridge_state;
pub mod error_codes;
pub mod validate;

mod bridge_id;
pub use bridge_id::generate_bridge_id;

// ---------------------------------------------------------------------------
// HTML escaping for event output (XSS prevention)
// ---------------------------------------------------------------------------

/// Escapes HTML-special characters in event output strings.
///
/// Prevents XSS when event output (which may contain attacker-controlled
/// strings from consequence rules, capability names, or member DIDs) is
/// inserted into DOM via `innerHTML` or similar mechanisms.
///
/// Replaces:
/// - `&` → `&amp;`
/// - `<` → `&lt;`
/// - `>` → `&gt;`
/// - `"` → `&quot;`
/// - `'` → `&#x27;`
///
/// This function is used by all FFI bridges (`PyO3`, napi-rs, `UniFFI`, WASM)
/// to sanitize event strings before returning them to callers.
#[inline]
#[must_use]
pub fn html_escape_event_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            _ => result.push(ch),
        }
    }
    result
}

/// Escapes HTML-special characters in a JSON string using JSON unicode
/// escapes.
///
/// This variant is for the WASM bridge where output is JSON. Using JSON
/// unicode escapes (`\u003c` etc.) keeps the output valid JSON while
/// preventing XSS when the JSON is inserted into HTML.
///
/// Replaces:
/// - `<` → `\u003c`
/// - `>` → `\u003e`
/// - `&` → `\u0026`
/// - `'` → `\u0027`
#[inline]
#[must_use]
pub fn html_escape_json(json: &str) -> String {
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\'', "\\u0027")
}

// Shared attestation construction pipeline for all non-WASM bridges.
// Requires scp-core + scp-identity (behind `resolvers` feature). Not available for WASM.
#[cfg(feature = "resolvers")]
pub mod attestation;

// Self-contained bridge instance replacing process-global OnceLock singletons.
// Requires scp-core (behind `resolvers` feature). Not available for WASM.
#[cfg(feature = "resolvers")]
pub mod bridge_instance;

// Re-export the public bridge-instance surface so callers do not need to
// `use scp_ffi_common::bridge_instance::CoreFields`.
#[cfg(feature = "resolvers")]
pub use bridge_instance::{
    BridgeInstance, BridgeInstanceCore, CoreFields, HandleAffinityError, LifecycleError,
    ShutdownError, ShutdownOutcome, TransportLockError, UNSET_INSTANCE_ID,
};

// Shared runtime helpers (key resolver, BridgeInMemoryStorage, event log provider).
// Requires scp-core + scp-platform (behind `resolvers` feature). Not available for WASM.
#[cfg(feature = "resolvers")]
pub mod bridge_runtime;

// Shared context-parameter builder for all non-WASM bridges.
// Requires scp-core (behind `resolvers` feature). Not available for WASM.
#[cfg(feature = "resolvers")]
pub mod context_params;

// Trust store shared across PyO3, napi-rs, and UniFFI bridges.
// Requires scp-core (behind `resolvers` feature). Not available for WASM.
#[cfg(feature = "resolvers")]
pub mod trust_store;

// All resolver types below require the `resolvers` feature (scp-core, scp-identity, tokio).
// WASM uses `default-features = false` to get only the `validate` module.
#[cfg(feature = "resolvers")]
mod resolvers;

#[cfg(feature = "resolvers")]
pub use resolvers::*;

// Discovery result mapping (ContextDiscoverySource → trust/resolution metadata).
// Requires scp-core types. Not available for WASM (ADR-034).
#[cfg(feature = "resolvers")]
pub mod discovery;

// Shared petname/handle/address-resolution helpers (behind the `resolvers` feature).
// WASM reimplements PetnameMap locally per ADR-034, so these are not available there.
#[cfg(feature = "resolvers")]
pub mod petname_helpers;

// Shared test helpers for FFI bridge tests (behind the `testing` feature).
#[cfg(feature = "testing")]
pub mod test_helpers;

// Shared relay/node startup code for FFI bridges that need to spawn servers.
// Requires scp-transport, scp-node, scp-platform, tokio. Not available for WASM (ADR-034).
#[cfg(feature = "server")]
pub mod server;
