//! Shared types for SCP FFI bridges.
//!
//! Two module groups:
//!
//! - **`validate`** — Input validation (always available, no external deps).
//!   Used by all bridges (`PyO3`, napi-rs, `UniFFI`, WASM).
//!
//! - **Resolver adapters** (behind `resolvers` feature) — Bridge `scp-core`'s
//!   validation traits to the FFI runtime. Requires scp-core, scp-identity,
//!   tokio. Not available for WASM (ADR-034).
//!
//! See §3.10.10, §9.5, §7.4.1 in `.docs/specs/`.

pub mod validate;

// All resolver types below require the `resolvers` feature (scp-core, scp-identity, tokio).
// WASM uses `default-features = false` to get only the `validate` module.
#[cfg(feature = "resolvers")]
mod resolvers;

#[cfg(feature = "resolvers")]
pub use resolvers::*;
