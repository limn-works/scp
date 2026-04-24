//! Deferred E2E crypto provider (ADR-049 commit 12c.9f).
//!
//! The pre-12c.9e `E2eCryptoProvider` was a dedicated trait impl that
//! bridged a shared `KeyExchange` across separate crypto instances so
//! Welcome + sender-key material could cross node boundaries in
//! `FullStackNetwork` tests. After ADR-049 commit 12c.9e the
//! `ContextCryptoProvider` trait is deleted — `ContextManager` binds to
//! the concrete `MlsCryptoProvider`. Re-implementing Welcome capture
//! on the concrete provider requires backend injection (12c.9f).
//!
//! Until that lands, this module exposes a thin
//! `E2eCryptoProvider` newtype around `Arc<MlsCryptoProvider>` so the
//! rest of the `fullstack/` module continues to type-check. Tests
//! that exercise the Welcome / key-exchange code paths are `#[ignore]`d
//! at their callsites pending 12c.9f.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::unused_self,
    clippy::type_complexity,
    unused_imports,
    dead_code,
    reason = "Deferred stubs pending ADR-049 commit 12c.9f MlsBackend injection."
)]

use std::sync::Arc;

use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_identity::DID;

use super::exchange::KeyExchange;

/// Deferred stand-in for the pre-12c.9e `E2eCryptoProvider`. Holds the
/// concrete `MlsCryptoProvider` (via `Arc`) plus a shared
/// [`KeyExchange`] so the public API surface remains unchanged.
pub struct E2eCryptoProvider {
    /// Real crypto provider — all actual MLS/sender-key work flows
    /// through this field.
    pub provider: Arc<MlsCryptoProvider>,
    /// Shared key-exchange side channel across `FullStackNetwork`
    /// nodes. Retained for API compatibility; Welcome/sender-key
    /// deposit/pickup helpers are no-ops until 12c.9f.
    #[allow(dead_code)]
    exchange: Arc<std::sync::Mutex<KeyExchange>>,
    /// This node's DID (for debugging / telemetry).
    #[allow(dead_code)]
    pub local_did: DID,
}

impl E2eCryptoProvider {
    /// Constructs a new deferred E2E crypto provider bound to the
    /// given DID.
    #[must_use]
    pub fn new(did: DID, exchange: Arc<std::sync::Mutex<KeyExchange>>) -> Self {
        let provider = Arc::new(MlsCryptoProvider::new(did.as_ref().to_owned()));
        Self {
            provider,
            exchange,
            local_did: did,
        }
    }

    /// Deposit an access key into the shared exchange so a joining node
    /// can pick it up. No-op pending 12c.9f Welcome plumbing.
    pub fn deposit_access_key(
        &self,
        _context_id: &str,
        _target_joiner_did: &str,
        _member_did: &DID,
        _key: scp_core::crypto::access_keys::AccessKey,
    ) {
        // Deferred to 12c.9f — access-key exchange requires Welcome
        // capture, which in turn requires backend injection on
        // MlsCryptoProvider.
    }

    /// Store an access key in this provider's local store. No-op
    /// pending 12c.9f plumbing.
    pub fn set_access_key(
        &self,
        _context_id: &str,
        _member_did: &str,
        _key: scp_core::crypto::access_keys::AccessKey,
    ) {
        // Deferred to 12c.9f.
    }

    /// Pick up all access keys deposited for this node by a previous
    /// `deposit_access_key` call. No-op pending 12c.9f.
    pub fn pickup_access_keys(&self, _context_id: &str) {
        // Deferred to 12c.9f.
    }

    /// Join an MLS group from a Welcome captured in the shared
    /// exchange. Returns `Ok(())` without side effects pending 12c.9f.
    pub fn join_from_welcome(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        // Deferred to 12c.9f — real implementation requires Welcome
        // capture on MlsCryptoProvider.
        Ok(())
    }

    /// Distribute this node's sender key to the target DID via the shared
    /// exchange. Returns `Ok(())` without side effects pending 12c.9f.
    pub fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        _target_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        // Deferred to 12c.9f — sender-key distribution requires backend
        // injection on MlsCryptoProvider.
        Ok(())
    }
}
