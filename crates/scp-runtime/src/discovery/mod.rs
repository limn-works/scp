//! Tool-interface discovery — async runtime.
//!
//! Pure types are in scp-protocol::discovery. This module retains the async
//! modules: addressing, search, did_capabilities, bootstrap, dht_context.

pub mod addressing;
pub mod bootstrap;
pub mod dht_context;
pub mod did_capabilities;
pub mod search;
