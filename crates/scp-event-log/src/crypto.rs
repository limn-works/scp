//! Shared Ed25519 signature verification helpers for the event log.
//!
//! Re-exports [`scp_crypto`] as the single source of truth. See
//! that module for full documentation.
//!
//! Before `scp-primitives` existed, this module duplicated the verification
//! function from `scp-core` to avoid a circular dependency. Now both crates
//! depend on `scp-primitives` (see GitHub issue #233).

pub use scp_crypto::verify_ed25519_signature;
