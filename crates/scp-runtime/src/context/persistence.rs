//! `ContextPersistence` trait — durable storage seam for context state.
//!
//! Hoisted to its own module in ADR-049 §15 ahead of the
//! `manager/` directory deletion. This module is the canonical home of
//! the trait and its no-op stub.

use super::state::ContextSnapshot;
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// ContextPersistence -- unified persistence provider
// ---------------------------------------------------------------------------

/// Provider for persisting full context state across process restarts.
///
/// This is the single persistence trait for ALL context state. Broadcast
/// security + roster state (author key epochs, subscriber registry, block
/// lists) is NOT a separate seam: it rides the full [`ContextSnapshot`]
/// (`ContextSnapshot::broadcast`), so `persist_context` / `load_context` carry
/// it atomically with the rest of the state — a governance ban / per-author
/// block / key-epoch advance is durable in ONE fail-closed row alongside
/// `read_exclusion_list` (ADR-049 §9, §5.14.8 block-before-serve). The former
/// best-effort `persist_broadcast` / `load_broadcast` methods (a separate
/// warn-and-continue write path) are gone.
///
/// # Async trait (ADR-049 Decision 7)
///
/// This is an `#[async_trait]` async trait: methods `.await` the underlying
/// storage directly instead of blocking on it via
/// `tokio::task::block_in_place` + `Handle::block_on` (the deleted
/// `ProtocolRepositoryContextBridge` sync→async shim). Implementors must be
/// dyn-compatible (`Send + Sync`, no generics, no RPITIT); `async_trait`
/// preserves that by desugaring each method to a boxed future.
///
/// **Send futures — NOT `#[async_trait(?Send)]`.** The trait object is held as
/// `Arc<dyn ContextPersistence>` owned inside `ActorDeps`, which is moved by
/// value into `tokio::spawn(actor.run())`. `tokio::spawn` requires
/// `Send + 'static`, so the desugared method futures MUST be `Send` — hence
/// plain `#[async_trait]`. This is deliberately asymmetric with
/// `RecoveryBackend` (ADR-049 Decision 7 PR-0), which is `#[async_trait(?Send)]`
/// because it is never held across a `tokio::spawn` boundary.
///
/// `persist_context` / `load_context` are the security-critical seam (called
/// fail-closed via `persist_state_fail_closed`); the other methods carry
/// best-effort semantics.
///
/// The canonical implementation is `ProtocolRepositoryContextBridge<S>` which
/// wraps `Arc<ProtocolRepository<S>>`.
///
/// See spec section 17.4.
#[async_trait]
pub trait ContextPersistence: Send + Sync {
    /// Persists the full context snapshot.
    ///
    /// Called after each context-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    async fn persist_context(
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
    async fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes all persisted state for a context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage delete fails.
    async fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Lists all persisted context IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage list fails.
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// NoOpContextPersistence — every operation is a no-op success.
// ---------------------------------------------------------------------------

/// No-op persistence — every operation is a no-op success.
///
/// Used by the supervisor's `Supervisor::for_query_shim`
/// constructor and as the default when [`crate::context::supervisor::Supervisor::with_providers`]
/// is called with `persistence: None`.
pub struct NoOpContextPersistence;

#[async_trait]
impl ContextPersistence for NoOpContextPersistence {
    async fn persist_context(
        &self,
        _context_id: &str,
        _snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}
