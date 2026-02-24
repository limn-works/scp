//! Cryptographic modules for SCP.
//!
//! This module contains the cryptographic primitives and protocol wrappers
//! used by SCP:
//!
//! - [`mls`] — MLS (Messaging Layer Security, RFC 9420) group encryption.
//!   Every SCP context is one MLS group. See ADR-001.
//!
//! Future modules (separate stories):
//! - `sender_keys/` — Per-sender AES-256 symmetric key layer (ADR-007).

pub mod mls;
pub mod sender_keys;
