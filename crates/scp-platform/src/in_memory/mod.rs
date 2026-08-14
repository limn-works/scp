//! In-memory, durability-only platform adapter implementations.
//!
//! This module houses the two platform adapters whose in-memory arm is a
//! **durability-only affordance** (spec §17.17.2 durability-only-vs-nullifier
//! classification), not a security nullifier:
//!
//! - [`InMemoryStorage`] — an in-memory [`Storage`](crate::traits::Storage)
//!   backend. It may lose state on process restart but nullifies **no**
//!   security or verifiability property: a restarted process with lost state
//!   cannot present a false guarantee, it simply has no state (it fails
//!   **closed**, not open).
//! - [`InMemoryPush`] — an in-memory [`Push`](crate::traits::Push) backend
//!   that mints synthetic tokens and passes payloads through as wake signals.
//!
//! Because they destroy no guarantee, spec §17.17 governs them as
//! durability-only arms: they MAY be compiled into any build and selected
//! **explicitly** (e.g. via `StorageConfig`), but MUST NOT be a default
//! (selection is mandatory / no silent default), a fallback from a failed
//! production selection, or the sole reachable arm for their capability in a
//! shipped SDK. Each type is gated behind its own durability-only cargo
//! feature (`in-memory-storage` / `in-memory-push`) so a crate may compile in
//! the durable dev affordance **without** pulling in the test-only nullifier
//! doubles that live in [`testing`](crate::testing) behind the `testing`
//! feature.
//!
//! The durability-vs-nullifier split is *not* inferable from the module name
//! alone (ADR-062 §0 Module-naming note): `in_memory/` encodes only
//! "shippable durability-only" versus [`testing`](crate::testing)'s
//! "test-only." The classification itself lives in spec §17.17.2.
//!
//! See ADR-006 in `.docs/adrs/phase-1.md` for the original design rationale
//! and ADR-062 §0 for the honest-module-structure split.
//!
//! # Example
//!
//! ```rust,ignore
//! use scp_platform::in_memory::InMemoryStorage;
//! use scp_platform::Storage;
//!
//! let storage = InMemoryStorage::new();
//! storage.store("key", b"value").await?;
//! ```

#[cfg(feature = "in-memory-storage")]
mod storage;
#[cfg(feature = "in-memory-storage")]
pub use storage::InMemoryStorage;

#[cfg(feature = "in-memory-push")]
mod push;
#[cfg(feature = "in-memory-push")]
pub use push::InMemoryPush;
