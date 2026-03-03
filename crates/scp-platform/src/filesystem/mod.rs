//! Filesystem-backed [`Storage`] implementation.
//!
//! Maps keys to file paths under a base directory. Values are written
//! atomically (write to temp file, then rename). Useful for server-side
//! deployments where inspectability matters.
//!
//! See spec section 17.6.
