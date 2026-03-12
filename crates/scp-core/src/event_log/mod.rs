//! Event log adapter for SCP contexts.
//!
//! Re-exports removed — import directly from [`scp_event_log`].
//! SCP has not shipped, so no backward compatibility is needed.
//!
//! The `KeyCustodySigner` adapter bridges `scp-platform`'s `KeyCustody`/`KeyHandle`
//! to the [`EventLogSigner`] trait defined in `scp-event-log`.
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.

// ---------------------------------------------------------------------------
// KeyCustodySigner adapter
// ---------------------------------------------------------------------------

use scp_event_log::EventLogSigner;
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
