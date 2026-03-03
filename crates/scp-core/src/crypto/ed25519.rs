//! Shared Ed25519 signature verification helpers.
//!
//! Re-exports [`scp_primitives::crypto`] as the single source of truth. See
//! that module for full documentation.
//!
//! Before `scp-primitives` existed, this module contained the canonical
//! implementation that `scp-event-log` duplicated locally. Now both crates
//! depend on `scp-primitives` (see GitHub issue #233).

pub use scp_primitives::crypto::{verify_ed25519_signature, verify_ed25519_signature_strict};
