//! Cryptographic modules for SCP.
//!
//! This module contains the cryptographic primitives and protocol wrappers
//! used by SCP:
//!
//! - [`access_keys`] — Content access key layer: per-member AES-256 access keys,
//!   CEK wrapping with AES-256-KW, and the `WrappedContent` wire format (ADR-038, §9.17).
//! - [`ed25519`] — Shared Ed25519 signature verification helpers.
//! - [`key_continuity`] — Key continuity fingerprint computation (spec section 9.11, ADR-039).
//! - [`tofu`] — Trust On First Use (TOFU) key tracking and comparison (spec section 9.11).
//! - [`mls`] — MLS (Messaging Layer Security, RFC 9420) group encryption.
//!   Every SCP context is one MLS group. See ADR-001.
//! - [`sender_keys`] — Per-sender AES-256 symmetric key layer (ADR-007).
//! - [`ucan`] — UCAN token types and capability enforcement (ADR-016).
//! - [`canonical`] — Canonical hash construction for signed structures (§9.5.1).

pub mod access_keys;
mod bip39_wordlist;
pub mod canonical;
pub mod ed25519;
pub mod key_continuity;
pub mod mls;
pub mod sender_keys;
pub mod tofu;
pub mod ucan;

#[cfg(test)]
mod agent_binding_tests;
