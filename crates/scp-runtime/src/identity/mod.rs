//! Identity types and utilities — async runtime.
//!
//! Pure types are in scp-protocol::identity. This module retains the async
//! modules: blocking, recovery, custody_migration, scpid.

pub mod blocking;
pub mod custody_migration;
pub mod recovery;
pub mod scpid;

// Re-export pure modules from scp-protocol.
pub use scp_protocol::identity::attestation;
pub use scp_protocol::identity::block_list;
pub use scp_protocol::identity::private_state;
pub use scp_protocol::identity::private_state_events;
pub use scp_protocol::identity::{SigningKeyId, extract_public_key_from_did};
