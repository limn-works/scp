//! Error types for the SCP participant driver.
//!
//! [`ClientError`] is the single error surfaced by every [`crate::ScpClient`]
//! operation. It wraps the shared lower-layer errors ([`scp_mls::MlsError`],
//! [`scp_protocol::crypto::sender_keys::SenderKeyError`],
//! [`scp_event_log::EventLogError`]) via `#[from]` so the driver bodies can use
//! `?` without re-deriving error taxonomies.

use scp_event_log::EventLogError;
use scp_mls::MlsError;
use scp_protocol::crypto::sender_keys::SenderKeyError;

/// Errors produced by the SCP participant driver.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// An MLS group operation failed (create/add/join/encrypt/decrypt/commit).
    #[error("MLS error: {0}")]
    Mls(#[from] MlsError),

    /// A sender-key (§9.16) layer operation failed.
    #[error("sender key error: {0}")]
    SenderKey(#[from] SenderKeyError),

    /// An event-log append or proof operation failed.
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),

    /// A TLS-codec (de)serialization of an MLS wire object failed.
    #[error("MLS wire codec error: {0}")]
    Codec(String),

    /// The requested context is not known to this client.
    #[error("unknown context: {0}")]
    UnknownContext(String),

    /// A context with the requested id already exists in this client.
    #[error("context already exists: {0}")]
    ContextAlreadyExists(String),

    /// The decrypted MLS message was not an application message (it was a
    /// commit or proposal) when an application message was expected.
    #[error("expected application message, got control message")]
    NotApplicationMessage,

    /// A driver invariant was violated (e.g. missing sender key for a member
    /// that is in the membership set, or a malformed driver argument).
    #[error("driver error: {0}")]
    Driver(String),
}
