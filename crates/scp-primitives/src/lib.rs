#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Shared low-level primitives for the SCP workspace.
//!
//! This crate exists to break the dependency cycle between `scp-core` and
//! `scp-event-log`. Both crates need clock utilities ([`time`]) and Ed25519
//! signature verification ([`crypto`]), but `scp-event-log` cannot depend on
//! `scp-core` without creating a circular dependency.
//!
//! Before this crate, the utilities were duplicated across both crates with
//! divergence tests to prevent silent drift (PR #222). Now both crates
//! depend on `scp-primitives` as the single source of truth.
//!
//! # Design Constraints
//!
//! - **Minimal dependencies.** Only `ed25519-dalek`, `serde`, and `z-base-32`
//!   beyond `std`. No protocol knowledge, no transport, no platform traits.
//! - **No async.** All functions are synchronous.
//! - **Leaf crate.** Must never depend on any other SCP crate.
//!
//! See GitHub issue #233 and PR #199 (scp-event-log extraction) for context.

pub mod crypto;
pub mod identity;
pub mod time;

pub use identity::{DID, SigningKeyId, did_dht_from_public_key, extract_public_key_from_did};

// Re-export Clock types at the crate root for convenience.
pub use time::{Clock, SystemClock, TestClock};
