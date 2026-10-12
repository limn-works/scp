//! Test-only platform adapter implementations.
//!
//! This module provides in-memory versions of the platform traits whose
//! in-memory arm is a **security nullifier** (spec §17.17.2
//! durability-only-vs-nullifier classification) — an arm that voids a security
//! or verifiability property the capability is responsible for, and which
//! therefore MUST be provably absent from shipped production artifacts (spec
//! §17.17 nullifier arms provably-absent):
//!
//! - [`InMemoryKeyCustody`] — stores private key material in unprotected heap
//!   memory (nullifies key confidentiality vs. hardware custody).
//! - [`InMemoryDeviceAttestation`] — always attests (nullifies attestation).
//! - [`InMemoryPreRotationCustody`] — in-memory pre-rotation commitment store.
//!
//! It also provides [`InMemoryPush`], a test double for the
//! [`Push`](crate::traits::Push) trait: its token is a UUID that no push
//! service issued, so it delivers no wake, and only tests construct it.
//!
//! They are gated behind the `testing` feature so production builds compiling
//! `software_platform` (for crypto primitives) do NOT compile these doubles.
//! The durability-only in-memory storage adapter lives in the
//! [`in_memory`](crate::in_memory) module instead — see ADR-062 §0 (amended
//! 2026-10-12) for the honest-module-structure split.
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the full design rationale.
//!
//! # Deterministic Testing
//!
//! [`InMemoryKeyCustody`] accepts an optional seed for deterministic key
//! generation, enabling reproducible test scenarios.
//!
//! # Example
//!
//! ```rust,ignore
//! use scp_platform::testing::InMemoryKeyCustody;
//! use scp_platform::{KeyCustody, KeyType};
//!
//! let custody = InMemoryKeyCustody::new();
//! let handle = custody.generate_keypair(KeyType::Ed25519).await?;
//! ```

mod attestation;
mod key_custody;
mod pre_rotation_custody;
mod push;

pub use attestation::InMemoryDeviceAttestation;
pub use key_custody::InMemoryKeyCustody;
pub use pre_rotation_custody::InMemoryPreRotationCustody;
// `lib.rs` already gates this module behind `testing`. The re-export repeats
// the gate because scp-testing's `test_double_gating` test parses each file
// alone and fails on a re-export of `InMemoryPush` that carries no gate.
#[cfg(feature = "testing")]
pub use push::InMemoryPush;
