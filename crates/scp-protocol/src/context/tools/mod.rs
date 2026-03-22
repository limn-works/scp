//! Tool registration, schema validation, and verification for SCP — pure protocol types.
//!
//! ToolSchema, ToolError types and pure module declarations.
//! Async modules (invoke, session) stay in scp-runtime.

pub mod integrity;
pub mod interface;
pub mod lifecycle;
pub mod registry;
pub mod schema;
pub mod summary;
