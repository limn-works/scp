//! `ContextPersistence` trait — durable storage seam for context state.
//!
//! Hoisted to its own module in ADR-049 commit 12 ahead of the
//! `manager/` directory deletion. Re-exports the trait from the
//! transitional location so downstream callers (FFI bridges, scp-core
//! re-exports) need not change paths in the same commit.
//!
//! Once `manager/` is deleted, this module becomes the authoritative
//! home of the trait.

pub use crate::context::manager::ContextPersistence;
