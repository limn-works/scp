//! Offline/sync strategy — async runtime.
//!
//! Pure types are in scp-protocol::sync. This module retains the async
//! modules: days_offline, hours_offline, weeks_offline.

pub mod days_offline;
pub mod hours_offline;
pub mod weeks_offline;

// Re-export pure modules from scp-protocol.
pub use scp_protocol::sync::alerts;
pub use scp_protocol::sync::conflict_resolution;
pub use scp_protocol::sync::*;
