//! Shared per-context bridge connector state for FFI bridges.
//!
//! All non-WASM FFI bridges (`PyO3`, napi-rs, `UniFFI`) maintain per-context
//! [`ShadowRegistry`] and [`SenderKeyStore`] instances across bridge function
//! calls. Without this persistent state, each call to `bridge_create_shadow`
//! would create ephemeral registries that are dropped when the function returns.
//!
//! This module provides the shared type definitions. The per-context state
//! is owned by [`CoreFields::bridge_state`](crate::bridge_instance::CoreFields)
//! and accessed via `bridge_instance().bridge_state()`.
//!
//! Gated behind the `resolvers` feature (not available for WASM — ADR-034).
//!
//! See spec section 12 (Bridge System) and ADR-023.

use scp_protocol::bridge::shadow::ShadowRegistry;
use scp_protocol::crypto::sender_keys::SenderKeyStore;

// ---------------------------------------------------------------------------
// BridgeContextState
// ---------------------------------------------------------------------------

/// Per-context bridge connector state that persists across function calls.
///
/// Without this, `bridge_create_shadow` would create ephemeral
/// `ShadowRegistry` and `SenderKeyStore` instances that are dropped when the
/// function returns, losing all shadow identity and sender key state.
///
/// Keyed by context ID in [`CoreFields::bridge_state`](crate::bridge_instance::CoreFields).
pub struct BridgeContextState {
    /// Shadow identity registry for this context.
    pub shadow_registry: ShadowRegistry,
    /// Sender key store for shadow envelope encryption.
    pub sender_key_store: SenderKeyStore,
}
