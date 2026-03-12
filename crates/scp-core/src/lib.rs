//! Core protocol implementation for SCP (Shared Context Protocol).
//!
//! `scp-core` contains the cryptographic and protocol logic that all SCP
//! clients share:
//!
//! - [`crypto::mls`] — MLS (Messaging Layer Security) group encryption wrapper.
//!   Every SCP context maps to one MLS group. Provides create, add member,
//!   remove member, and destroy operations. See ADR-001.
//!
//! # Architecture
//!
//! `scp-core` depends on `scp-platform` for platform abstraction traits
//! (key custody, storage). It does not depend on any transport layer — the
//! core is purely about identity, crypto, and protocol logic.
//!
//! See `.docs/architecture.md` for the full crate layout and build phases.

// `deny` (not `forbid`) to allow a narrow `#[allow(unsafe_code)]` exception
// in `crypto::mls::group::zeroize_signature_key_pair`, which must use unsafe
// pointer access to zeroize private key bytes inside an upstream type whose
// private field has no public accessor. See issue #601.
#![deny(unsafe_code)]

pub mod bridge;
pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod event_log;
pub mod identity;
pub mod provenance;
pub mod serde_util;
pub mod store;
pub mod sync;
pub mod time;
pub mod trust;
pub mod uri;
pub mod well_known;

// Re-export the MLS module's primary types at the crate level for convenience.
pub use crypto::mls;
