//! MLS wrapper for group key agreement. See ADR-001.
//!
//! This module wraps `OpenMLS` to provide SCP-specific group encryption
//! operations. All SCP contexts map to MLS groups; membership is
//! enforced cryptographically through MLS group keys.
//!
//! # Ciphersuite
//!
//! SCP uses a single, fixed ciphersuite: X25519 for key exchange,
//! AES-128-GCM for encryption, SHA-256 for hashing, and Ed25519 for
//! signing. No ciphersuite negotiation in v1 (eliminates downgrade
//! attacks).
//!
//! # Sub-modules
//!
//! - [`credential`] -- SCP credential type (DID + UCAN) for MLS leaf nodes.
//! - [`error`] -- MLS-specific error types wrapping `OpenMLS` errors.
//! - [`storage`] -- Storage bridge from `OpenMLS` to SCP platform adapters.

pub mod credential;
pub mod error;
pub mod storage;

use openmls_traits::types::Ciphersuite;

/// The single MLS ciphersuite used by SCP.
///
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001):
/// - **Key exchange:** X25519 (Curve25519 ECDH)
/// - **Encryption:** AES-128-GCM
/// - **Hash:** SHA-256
/// - **Signature:** Ed25519
///
/// No ciphersuite negotiation exists in SCP v1. This eliminates
/// downgrade attacks and simplifies implementation. This is the
/// MLS mandatory-to-implement (MTI) ciphersuite per RFC 9420.
///
/// See ADR-001 for rationale.
pub const SCP_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
