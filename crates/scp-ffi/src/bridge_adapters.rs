//! Shared bridge adapter types for the UCAN validation pipeline.
//!
//! Re-exports from [`scp_ffi_common`] so that existing imports from
//! `crate::bridge_adapters` continue to work.

pub use scp_ffi_common::{
    BridgeDidResolver, BridgeNonceTracker, BridgeProofResolver, BridgeRevocationChecker,
};
