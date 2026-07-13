//! Outlet registration, invocation, and session management — async runtime.
//!
//! Pure types are in `scp-protocol::context::outlets`. This module retains
//! the async modules: invoke, session.

pub mod dispatch;
pub mod invoke;
pub mod session;
pub mod signer;
pub mod stream;
pub mod stream_counter_adapter;
pub mod stream_settlement_adapter;
