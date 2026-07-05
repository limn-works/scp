//! Synchronous MLS (Messaging Layer Security) state machine for SCP.
//!
//! This crate holds the **synchronous** MLS group operations lifted out of
//! `scp-runtime` so they can compile to `wasm32-unknown-unknown` and be shared
//! by both the native node runtime and in-browser SCP clients (ADR-057).
//!
//! Every SCP context maps to one MLS group. The wrapper exposes SCP-specific
//! lifecycle operations and hides `OpenMLS` internals behind a clean interface.
//!
//! # Mechanical fence (ADR-057 scope fence)
//!
//! `scp-mls` depends only on `scp-clock`, `scp-did`, `scp-protocol`, and the
//! `openmls` stack. It **must not** depend on `scp-runtime` (tokio/actor
//! orchestration) or `scp-identity` (tokio-coupled custody/DHT). The async
//! durable-storage bridge (`ScpMlsProvider<S>`, the `block_in_place` storage
//! adapters) stays in `scp-runtime`; only the in-memory provider alias lives
//! here.
//!
//! # Ciphersuite
//!
//! All groups use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (no
//! ciphersuite negotiation). See ADR-001 for the rationale.
//!
//! # Modules
//!
//! - [`group`] — Group lifecycle: create, add member, remove member, destroy.
//! - [`credential`] — SCP credential type (DID + UCAN) for MLS `LeafNode` fields.
//! - [`encrypt`] — Application-message encrypt/decrypt over the MLS group.
//! - [`ratchet`] — Commit processing and epoch advance.
//! - [`key_package`] — Single-use `KeyPackage` buffer management.
//! - [`lifetime`] — `KeyPackage` `Lifetime` minting/validation via the injected
//!   [`scp_clock::Clock`] (ADR-057 Prereq-1).
//! - [`wrapping_extension`] — `scp_wrapping_key` `LeafNode` extension helpers.
//! - [`epoch_grace`] — Epoch grace-window store (forward-secrecy bound).
//! - [`error`] — MLS-specific error types.
//!
//! See ADR-001 in `.docs/adrs/phase-1.md` for the MLS wrapper design and
//! ADR-057 for the `scp-mls` extraction.

pub mod credential;
pub mod encrypt;
pub mod epoch_grace;
pub mod error;
pub mod group;
pub mod key_package;
pub mod lifetime;
pub mod ratchet;
pub mod snapshot;
pub mod wrapping_extension;

// Re-export primary public API types for convenience.
pub use credential::ScpCredential;
pub use encrypt::{DecryptedContent, InboundChange};
pub use error::MlsError;

// The MLS signing key pair appears in this crate's public op signatures
// (`generate_key_package` returns it; `join_group` consumes it). Re-export it so
// consumers — notably the in-browser participant driver (ADR-057) — can name
// the type without taking a direct dependency on `openmls_basic_credential`.
pub use group::{
    AddMemberResult, RemoveMemberResult, SCP_CIPHERSUITE, ScpMlsGroup, add_member, create_group,
    create_group_with_wrapping_key, destroy_group, generate_key_package,
    generate_key_package_with_wrapping_key, join_group, key_package_in_did, remove_member,
};
pub use lifetime::{
    KEY_PACKAGE_LIFETIME_MARGIN_SECS, KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS,
    KEY_PACKAGE_LIFETIME_SECS, key_package_lifetime, validate_key_package_lifetime,
};
pub use openmls_basic_credential::SignatureKeyPair;
// The snapshot STRUCTS (`MlsGroupSnapshot`, `PendingJoinSnapshot`) are NOT
// re-exported: they have private fields, no public constructor, and appear in no
// public signature (serde reaches them through the free fns / methods, which does
// not need `pub`). Only the round-trip entry points are public API.
pub use snapshot::{restore_pending_join, serialize_pending_join};
pub use wrapping_extension::{
    SCP_WRAPPING_KEY_EXTENSION_TYPE, extract_member_wrapping_key, extract_own_wrapping_key,
    extract_wrapping_key, find_leaf_index_by_did, leaf_node_params_with_wrapping_key,
    make_wrapping_key_extension, scp_capabilities_with_wrapping_key,
};

/// The in-memory MLS provider type.
///
/// This is the `openmls_rust_crypto` provider with all key material held in
/// process memory. The native runtime's persistent `ScpMlsProvider<S>` (which
/// snapshots out to durable storage) wraps this; an in-browser client snapshots
/// it to `IndexedDB` out-of-band. Lifted out of `scp-runtime`'s `storage.rs` into
/// `scp-mls` so the sync MLS machine is self-contained (ADR-057).
///
/// See ADR-001 and ADR-006 for the storage provider strategy.
pub type InMemoryMlsProvider = openmls_rust_crypto::OpenMlsRustCrypto;
