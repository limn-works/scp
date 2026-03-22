//! Tool registration, invocation, and session management — async runtime.
//!
//! Pure types are in scp-protocol::context::tools. This module retains
//! the async modules: invoke, session.

pub mod invoke;
pub mod session;

// Re-export pure modules from scp-protocol.
pub use scp_protocol::context::tools::integrity;
pub use scp_protocol::context::tools::interface;
pub use scp_protocol::context::tools::lifecycle;
pub use scp_protocol::context::tools::registry;
pub use scp_protocol::context::tools::schema;
pub use scp_protocol::context::tools::summary;
pub use scp_protocol::context::tools::*;
