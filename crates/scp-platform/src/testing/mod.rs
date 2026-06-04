//! In-memory platform adapter implementations for testing and development.
//!
//! This module provides in-memory versions of all four platform traits:
//! [`InMemoryKeyCustody`], [`InMemoryDeviceAttestation`], [`InMemoryPush`],
//! and [`InMemoryStorage`]. They provide identical API surfaces to production
//! adapters but store everything in memory with no external dependencies.
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
//! use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
//! use scp_platform::{KeyCustody, KeyType, Storage};
//!
//! let custody = InMemoryKeyCustody::new();
//! let handle = custody.generate_keypair(KeyType::Ed25519).await?;
//!
//! let storage = InMemoryStorage::new();
//! storage.store("key", b"value").await?;
//! ```

mod attestation;
mod key_custody;
mod pre_rotation_custody;
mod push;
mod storage;

pub use attestation::InMemoryDeviceAttestation;
pub use key_custody::InMemoryKeyCustody;
pub use pre_rotation_custody::InMemoryPreRotationCustody;
pub use push::InMemoryPush;
pub use storage::InMemoryStorage;
