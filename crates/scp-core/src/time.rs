//! Clock utilities with proper error handling.
//!
//! Re-exports [`scp_primitives::time`] as the single source of truth. See
//! that module for full documentation.
//!
//! Before `scp-primitives` existed, this module contained the canonical
//! implementation that `scp-event-log` duplicated locally. Now both crates
//! depend on `scp-primitives` (see GitHub issue #233).

pub use scp_primitives::time::{ClockError, now_millis, now_secs};
