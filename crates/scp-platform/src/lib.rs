#![forbid(unsafe_code)]
//! Platform abstraction traits for key custody, storage, attestation, and push.
//! See ADR-006.

pub mod traits;
pub use traits::*;
