//! Tool-interface discovery — async runtime.
//!
//! Pure types are in scp-protocol::discovery. This module retains the async
//! modules: addressing, search, did_capabilities, bootstrap, dht_context.

pub mod addressing;
pub mod bootstrap;
pub mod dht_context;
pub mod did_capabilities;
pub mod search;

// Re-export pure modules from scp-protocol.
pub use scp_primitives::DID;
pub use scp_protocol::discovery::context;
pub use scp_protocol::discovery::context::{AgentSearchParams, AgentSearchResult};
pub use scp_protocol::discovery::handles;
pub use scp_protocol::discovery::petnames;
pub use scp_protocol::discovery::push;
pub use scp_protocol::discovery::scope;
pub use scp_protocol::discovery::{
    ContextId, DataProvenance, DiscoveryError, DiscoveryQuery, DiscoveryResult,
    DiscoveryResultEntry, RegistrationEntry,
};
