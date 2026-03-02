//! Verifiable event log (Merkle tree) for SCP contexts.
//!
//! This module re-exports the standalone [`scp_event_log`] crate for full
//! backward compatibility. All types, functions, and submodules are available
//! at their original paths (`crate::event_log::*`).
//!
//! The `KeyCustodySigner` adapter bridges `scp-platform`'s `KeyCustody`/`KeyHandle`
//! to the [`EventLogSigner`] trait defined in `scp-event-log`.
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.

// Re-export all public items from scp-event-log.
pub use scp_event_log::checkpoint;
pub use scp_event_log::metrics;
pub use scp_event_log::proof;
pub use scp_event_log::pruning;
pub use scp_event_log::tiered_storage;
pub use scp_event_log::tree;
pub use scp_event_log::{
    ContextId, DID, Ed25519Signature, Event, EventLog, EventLogError, EventLogSigner, EventPayload,
    EventType,
};

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod test_helpers {
    pub use scp_event_log::test_helpers::*;
}

// ---------------------------------------------------------------------------
// KeyCustodySigner adapter
// ---------------------------------------------------------------------------

use scp_platform::traits::{KeyCustody, KeyHandle};

/// Adapter bridging `scp-platform`'s [`KeyCustody`]/[`KeyHandle`] to the
/// [`EventLogSigner`] trait defined in `scp-event-log`.
///
/// This allows checkpoint generation and other signing operations in `scp-core`
/// to use the platform's key custody implementation transparently.
pub struct KeyCustodySigner<'a, C: KeyCustody> {
    /// The key custody implementation.
    pub custody: &'a C,
    /// The signing key handle.
    pub key: &'a KeyHandle,
}

#[async_trait::async_trait]
impl<C: KeyCustody> EventLogSigner for KeyCustodySigner<'_, C> {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let sig = self
            .custody
            .sign(self.key, message)
            .await
            .map_err(|e| e.to_string())?;
        Ok(sig.into_bytes())
    }
}
