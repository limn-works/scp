//! Clock utilities with proper error handling.
//!
//! Re-exports [`scp_primitives::time`] as the single source of truth. See
//! that module for full documentation.
//!
//! Before `scp-primitives` existed, this module duplicated the clock
//! utilities from `scp-core` to avoid a circular dependency. Now both
//! crates depend on `scp-primitives` (see GitHub issue #233).

pub use scp_primitives::time::{ClockError, now_secs};
