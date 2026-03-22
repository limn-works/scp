//! Clock utilities.
//!
//! Re-exports the [`Clock`] trait and implementations from [`scp_primitives::time`].
//! Protocol-bound modules must use `&dyn Clock`.

pub use scp_primitives::time::{Clock, ClockError, SystemClock, TestClock};
