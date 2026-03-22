//! Tool registration, invocation, and session management — async runtime.
//!
//! Pure types are in scp-protocol::context::tools. This module retains
//! the async modules: invoke, session.

pub mod invoke;
pub mod session;
