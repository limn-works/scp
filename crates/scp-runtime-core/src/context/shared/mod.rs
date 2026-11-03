//! Shared domain items (ADR-070 §2 rule for each cross-boundary function).
//!
//! Each submodule holds the items one domain shares with core and with the
//! other domains: functions that read or write only core state and call no
//! domain function, and the types and constants that two or more crates name.

pub mod broadcast;
pub mod economy;
pub mod governance;
pub mod lifecycle;
pub mod messaging;
pub mod outlets;
pub mod queries;
pub mod standing;
pub mod trust_recovery;
pub mod ttl_close;
