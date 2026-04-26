//! Outlet registration, invocation, and session management — async runtime.
//!
//! Pure types are in `scp-protocol::context::outlets`. This module retains
//! the async modules: invoke, session, plus the §5.4.4 round-5 per-outlet
//! HMAC key derivation (`message_key`) and acceptance pin helper
//! (`registration`).

pub mod invoke;
pub mod message_key;
pub mod registration;
pub mod session;
