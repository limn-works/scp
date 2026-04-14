//! Shared per-context bridge connector state for FFI bridges.
//!
//! All non-WASM FFI bridges (`PyO3`, napi-rs, `UniFFI`) maintain per-context
//! [`ShadowRegistry`] and [`SenderKeyStore`] instances across bridge function
//! calls. Without this persistent state, each call to `bridge_create_shadow`
//! would create ephemeral registries that are dropped when the function returns.
//!
//! This module provides the shared type, global registry, and accessor functions
//! so each bridge avoids reimplementing the same `OnceLock<DashMap<String, ...>>`
//! boilerplate.
//!
//! Gated behind the `resolvers` feature (not available for WASM — ADR-034).
//!
//! See spec section 12 (Bridge System) and ADR-023.

use std::sync::OnceLock;

use dashmap::DashMap;
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
/// Keyed by context ID in the global [`bridge_state_registry`].
pub struct BridgeContextState {
    /// Shadow identity registry for this context.
    pub shadow_registry: ShadowRegistry,
    /// Sender key store for shadow envelope encryption.
    pub sender_key_store: SenderKeyStore,
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

/// Process-global registry of per-context bridge connector state.
///
/// Uses `DashMap` for lock-free concurrent reads, matching the pattern
/// used throughout the FFI bridges.
static BRIDGE_STATE: OnceLock<DashMap<String, BridgeContextState>> = OnceLock::new();

/// Returns a reference to the bridge state registry, initializing on first access.
pub fn bridge_state_registry() -> &'static DashMap<String, BridgeContextState> {
    BRIDGE_STATE.get_or_init(DashMap::new)
}

/// Removes per-context bridge state on context close, preventing unbounded
/// memory growth in long-running processes.
///
/// Called from each bridge's context-close or cleanup path.
pub fn remove_bridge_state(context_id: &str) {
    bridge_state_registry().remove(context_id);
}
