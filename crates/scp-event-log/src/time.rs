//! Clock utilities.
//!
//! Re-exports the [`Clock`] trait and implementations from [`scp_clock`].
//! Protocol-bound modules must use `&dyn Clock`.

pub use scp_clock::{Clock, SystemClock, TestClock};
