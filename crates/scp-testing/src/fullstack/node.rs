//! Full-stack test node — deferred to ADR-049 commit 12c.9f.
//!
//! The pre-12c.9e `FullStackNode` wrapped `ContextManager` with an
//! `E2eCryptoProvider` that bridged Welcome messages and sender keys
//! through a shared `KeyExchange`. That design depended on a custom
//! `ContextCryptoProvider` trait impl with extra (non-trait) methods
//! for Welcome capture, access-key deposit, and sender-key pickup.
//!
//! After ADR-049 commit 12c.9e, the trait is deleted and
//! `ContextManager` binds to the concrete `MlsCryptoProvider`.
//! Re-wiring the Welcome / sender-key side channel requires backend
//! injection on the concrete provider (commit 12c.9f). Until that
//! lands, `FullStackNode` is a compile-only stub: the struct and its
//! public surface are preserved so the FFI bridges that embed it keep
//! type-checking, but every method returns an error surfacing the
//! deferral.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::unused_self,
    clippy::type_complexity,
    clippy::unused_async,
    clippy::expect_used,
    dead_code,
    unused_imports,
    unused_variables,
    reason = "Deferred stubs pending ADR-049 commit 12c.9f MlsBackend injection."
)]

use std::sync::{Arc, Mutex};

use scp_core::context::builder::{ContextCreationError, ContextEventLogProvider};
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::ContextEvent;
use scp_core::context::providers::event_log::MerkleEventLogProvider;
use scp_core::context::{ContextError, ContextHandle, ContextManager, ContextParams};
use scp_identity::DID;

use super::crypto::E2eCryptoProvider;
use super::exchange::KeyExchange;

#[derive(thiserror::Error, Debug)]
#[error(
    "fullstack node operation deferred to ADR-049 commit 12c.9f \
     (MlsBackend injection replaces the ContextCryptoProvider trait impl)"
)]
pub struct DeferredError;

impl From<DeferredError> for ContextError {
    fn from(_: DeferredError) -> Self {
        Self::CryptoFailed(
            "fullstack operation deferred to 12c.9f (MlsBackend injection)".to_owned(),
        )
    }
}

impl From<DeferredError> for ContextCreationError {
    fn from(_: DeferredError) -> Self {
        Self::CryptoFailed(
            "fullstack operation deferred to 12c.9f (MlsBackend injection)".to_owned(),
        )
    }
}

/// Full-stack test node — deferred stub.
pub struct FullStackNode {
    /// This node's DID.
    pub did: DID,
    /// Real ContextManager, bound to a real MlsCryptoProvider.
    pub manager: Arc<ContextManager>,
    /// Deferred E2E crypto provider (thin newtype around the real
    /// `MlsCryptoProvider`). Kept for public-API compatibility.
    pub crypto: Arc<E2eCryptoProvider>,
    /// Merkle event log provider.
    pub event_log: Arc<MerkleEventLogProvider>,
    /// Buffer of captured ciphertexts — always empty in the deferred
    /// stub; full capture returns in 12c.9f.
    #[allow(dead_code)]
    sent: Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>,
    /// Deterministic signing key derived from the DID.
    #[allow(dead_code)]
    signing_key: ed25519_dalek::SigningKey,
}

fn did_to_seed(did: &DID) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.as_ref().hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    seed
}

impl FullStackNode {
    /// Constructs a new stub node bound to a real `MlsCryptoProvider`.
    #[must_use]
    pub fn new(did: DID, crypto: Arc<E2eCryptoProvider>, key_resolver: KeyResolver) -> Self {
        let event_log = Arc::new(MerkleEventLogProvider::new());
        let sent = Arc::new(Mutex::new(Vec::new()));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&did_to_seed(&did));

        let manager = scp_core::context::attach_test_supervisor(ContextManager::new(
            Arc::clone(&crypto.provider),
            Box::new(scp_core::context::NotConfiguredTransportProvider),
            Box::new(MerkleEventLogProvider::new()),
            key_resolver,
        ));

        Self {
            did,
            manager,
            crypto,
            event_log,
            sent,
            signing_key,
        }
    }

    /// Creates a context via the real `ContextManager`.
    ///
    /// # Errors
    ///
    /// Propagates `ContextCreationError` from `ContextManager`.
    pub async fn create_context(
        &self,
        context_id: &str,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        self.manager
            .create_context(context_id.to_owned(), params, self.did.clone(), None)
            .await
    }

    /// Adds a member — deferred.
    pub async fn add_member(
        &self,
        _handle: &ContextHandle,
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Err(DeferredError.into())
    }

    /// Joins from Welcome — deferred.
    pub fn join_from_welcome(
        &self,
        _context_id_str: &str,
        _context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        Err(DeferredError.into())
    }

    /// Copies access keys from the E2E provider to the manager — deferred.
    pub async fn sync_access_keys(&self, _context_id: &str) {
        // Deferred to 12c.9f.
    }

    /// Send message — deferred.
    pub async fn send_message(
        &self,
        _handle: &ContextHandle,
        _payload: &[u8],
    ) -> Result<(), ContextError> {
        Err(DeferredError.into())
    }

    /// Take the captured ciphertexts — always empty in the stub.
    #[must_use]
    pub fn take_sent_ciphertexts(&self) -> Vec<([u8; 32], Vec<u8>)> {
        std::mem::take(&mut *self.sent.lock().expect("sent buffer lock"))
    }

    /// Decrypt message — deferred.
    pub fn decrypt_message(
        &self,
        _context_id_str: &str,
        _context_id: &[u8; 32],
        _ciphertext: &[u8],
        _sender_did: &str,
    ) -> Result<Vec<u8>, ContextError> {
        Err(DeferredError.into())
    }

    /// Remove member — deferred.
    pub async fn remove_member(
        &self,
        _handle: &ContextHandle,
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Err(DeferredError.into())
    }

    /// Regenerate and distribute sender key — deferred.
    pub fn regenerate_and_distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        Err(DeferredError.into())
    }

    /// Pick up pending sender keys — deferred (no-op).
    pub fn pickup_sender_keys(&self, _context_id: &[u8; 32]) -> Result<(), ContextError> {
        Ok(())
    }

    /// Syncs access keys picked up from the shared exchange into the
    /// manager's per-context state. Deferred (no-op) pending 12c.9f.
    pub async fn sync_access_keys_to_manager(
        &self,
        _context_id: &str,
        _context_id_bytes: &[u8; 32],
    ) {
        // Deferred to 12c.9f — sync requires access-key pickup to have
        // done real work, which is backed by the Welcome-capture path.
    }

    /// Drain events via the real `ContextManager`.
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        self.manager.drain_events(context_id).await
    }

    /// Returns the Merkle root of the event log for a context.
    ///
    /// # Errors
    ///
    /// Returns error if no event log exists for the context.
    pub fn merkle_root(&self, context_id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        self.event_log.event_log_merkle_root(context_id)
    }
}

/// Constructs a new `KeyExchange` wrapped for shared ownership.
#[must_use]
pub fn new_key_exchange() -> Arc<Mutex<KeyExchange>> {
    Arc::new(Mutex::new(KeyExchange::new()))
}
