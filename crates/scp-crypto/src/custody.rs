//! A key custody failure carried as a typed value.
//!
//! The runtime reports a failed `KeyCustody` call through error types that
//! live in crates below `scp-platform` (`scp-protocol`, `scp-event-log`),
//! which therefore cannot hold a `PlatformError`. They hold a
//! [`CustodyFailure`] instead, and every bridge reads its [`CustodyFailureKind`]
//! to report `SCP-CRYPTO-4006` (key not found), `SCP-IDENT-1055` (a host
//! pseudonym the bridge rejects, ADR-021) or `SCP-CRYPTO-4060` (any other
//! custody failure), as `.docs/standards/sdk-common.md` registers them. A
//! pseudonym whose identity key was destroyed fails with key-not-found
//! (`09-security-model.md` §9.10.4.A).

/// Which custody failure occurred. The kind alone decides the error code a
/// bridge reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyFailureKind {
    /// The key handle is unknown or its key was destroyed.
    KeyNotFound,
    /// The bridge rejected a pseudonym the host custody derived.
    PseudonymRejected,
    /// The custody backend failed for any other reason.
    Failed,
}

/// A failed key custody call: its [`CustodyFailureKind`] and the backend's
/// description.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("key custody failed: {detail}")]
pub struct CustodyFailure {
    /// Which custody failure occurred.
    pub kind: CustodyFailureKind,
    /// The backend's description of the failure.
    pub detail: String,
}

impl CustodyFailure {
    /// Returns whether the key handle was unknown or its key destroyed.
    #[must_use]
    pub const fn is_key_not_found(&self) -> bool {
        matches!(self.kind, CustodyFailureKind::KeyNotFound)
    }
}

/// A signer that cannot fail (a software key in a test or a KAT) converts its
/// uninhabited error into a [`CustodyFailure`].
impl From<core::convert::Infallible> for CustodyFailure {
    fn from(never: core::convert::Infallible) -> Self {
        match never {}
    }
}
