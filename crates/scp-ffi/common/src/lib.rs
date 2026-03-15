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

pub mod validate;

mod bridge_id;
pub use bridge_id::generate_bridge_id;

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
