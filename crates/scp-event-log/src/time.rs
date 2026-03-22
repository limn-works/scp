//! Clock utilities.
//!
//! Re-exports the [`Clock`] trait and implementations from [`scp_primitives::time`].
//! Protocol-bound modules must use `&dyn Clock` — the free functions
//! `now_secs()`/`now_millis()` are intentionally NOT re-exported here.
//! Runtime modules that need them must import from `scp_primitives::time` directly.

pub use scp_primitives::time::{Clock, ClockError, SystemClock, TestClock};
