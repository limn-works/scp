//! `ContextPersistence` trait — durable storage seam for context state.
//!
//! Hoisted to its own module in ADR-049 commit 12 ahead of the
//! `manager/` directory deletion. This module is the canonical home of
//! the trait and its no-op stub.

use scp_protocol::context::broadcast::BroadcastContextSnapshot;

use super::state::ContextSnapshot;

// ---------------------------------------------------------------------------
// ContextPersistence -- unified persistence provider
// ---------------------------------------------------------------------------

/// Provider for persisting full context state across process restarts.
///
/// Replaces the previous `BroadcastPersistence` trait. This is the single
/// persistence trait for all context state: both the full context snapshot
/// (membership, roles, governance, TTL) and the broadcast-specific state
/// (author keys, subscribers, block lists).
///
/// Implementors must be dyn-compatible (`Send + Sync`, no generics, no
/// RPITIT). All methods return `Result<_, Box<dyn Error + Send + Sync>>`
/// for best-effort semantics: the supervisor logs errors but does
/// not abort mutations when persistence fails.
///
/// The canonical implementation is `ProtocolRepositoryContextBridge<S>` which
/// wraps `Arc<ProtocolRepository<S>>`.
///
/// See spec section 17.4.
pub trait ContextPersistence: Send + Sync {
    /// Persists the full context snapshot.
    ///
    /// Called after each context-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a previously persisted full context snapshot.
    ///
    /// Returns `None` if no snapshot exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Persists the broadcast context state snapshot.
    ///
    /// Called after each broadcast-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a previously persisted broadcast context snapshot.
    ///
    /// Returns `None` if no snapshot exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes all persisted state for a context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage delete fails.
    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Lists all persisted context IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage list fails.
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// NoopContextPersistence — every operation is a no-op success.
// ---------------------------------------------------------------------------

/// No-op persistence — every operation is a no-op success.
///
/// Used by the supervisor's [`crate::context::supervisor::Supervisor::for_query_shim`]
/// constructor and as the default when [`crate::context::supervisor::Supervisor::with_providers`]
/// is called with `persistence: None`.
pub struct NoopContextPersistence;

impl ContextPersistence for NoopContextPersistence {
    fn persist_context(
        &self,
        _context_id: &str,
        _snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    fn persist_broadcast(
        &self,
        _context_id: &str,
        _snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn load_broadcast(
        &self,
        _context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}
