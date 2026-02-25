//! MLS-derived key material for media sessions.
//!
//! Media session keys are derived from the MLS group state via
//! `exporter()` (RFC 9420 section 8). Keys are bound to the current MLS epoch,
//! so member removal automatically invalidates prior media keys.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

/// A context identifier string.
///
/// Represented as a plain `String`. Matches the type alias pattern used
/// across `scp-core` modules.
pub type ContextId = String;

/// DTLS-SRTP key material derived from MLS group state.
///
/// These keys bind media session security to context group membership.
/// Only current-epoch members can derive them. An MLS epoch advance
/// (triggered by member removal) invalidates prior keys, requiring
/// receivers to re-derive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaKeyMaterial {
    /// Raw DTLS-SRTP key bytes exported from the MLS group.
    pub dtls_srtp_keys: Vec<u8>,

    /// MLS epoch from which the keys were derived.
    pub epoch: u64,

    /// Context whose MLS group produced the key material.
    pub context_id: ContextId,
}
