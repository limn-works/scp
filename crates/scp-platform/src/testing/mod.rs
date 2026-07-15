//! Test-only, security-nullifier platform adapter implementations.
//!
//! This module provides in-memory versions of the platform traits whose
//! in-memory arm is a **security nullifier** (spec §17.17.2,
//! `SCP-CAPSEL-8010`) — an arm that voids a security or verifiability property
//! the capability is responsible for, and which therefore MUST be provably
//! absent from shipped production artifacts (`SCP-CAPSEL-8012`):
//!
//! - [`InMemoryKeyCustody`] — stores private key material in unprotected heap
//!   memory (nullifies key confidentiality vs. hardware custody).
//! - [`InMemoryDeviceAttestation`] — always attests (nullifies attestation).
//! - [`InMemoryPreRotationCustody`] — in-memory pre-rotation commitment store.
//!
//! They are gated behind the `testing` feature so production builds compiling
//! `software_platform` (for crypto primitives) do NOT compile these nullifier
//! doubles. The durability-only in-memory storage and push adapters live in
//! the [`in_memory`](crate::in_memory) module instead — see ADR-062 §0 for the
//! honest-module-structure split.
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

pub use attestation::InMemoryDeviceAttestation;
pub use key_custody::InMemoryKeyCustody;
pub use pre_rotation_custody::InMemoryPreRotationCustody;
