//! Offline/sync strategy — async runtime.
//!
//! Pure types are in `scp-protocol::sync`. This module retains the async
//! modules: `days_offline`, `hours_offline`, `weeks_offline`.

pub mod days_offline;
pub mod hours_offline;
pub mod weeks_offline;
