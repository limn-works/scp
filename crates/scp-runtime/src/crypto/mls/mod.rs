//! MLS (Messaging Layer Security) wrapper for SCP.
//!
//! The **synchronous** MLS state machine (`group`, `encrypt`, `ratchet`,
//! `credential`, `key_package`, `error`, `wrapping_extension`, `epoch_grace`,
//! and the `InMemoryMlsProvider` alias) was lifted into the wasm32-safe
//! [`scp_mls`] crate (ADR-057) so it can be shared by both the native node
//! runtime and in-browser SCP clients. This module re-exports those items
//! under their historical `crate::crypto::mls::*` paths so the rest of
//! `scp-runtime` compiles unchanged, and keeps the **async durable-storage
//! bridge** (`storage`, `provider`, `backend`, `production_backend`,
//! `storage_adapter`) — the `block_in_place`/`ScpMlsProvider<S>` parts that are
//! tokio-coupled and node-only.
//!
//! # Ciphersuite
//!
//! All groups use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (no
//! ciphersuite negotiation). See ADR-001 for the rationale.
//!
//! See ADR-001 in `.docs/adrs/phase-1.md` for the MLS wrapper design and
//! ADR-057 for the `scp-mls` extraction.

// Runtime-coupled tests for `scp_mls::wrapping_extension` that exercise the
// node-only sender-key protocol (carved out of the moved file; ADR-057).
#[cfg(test)]
mod wrapping_extension_runtime_tests;

// Async durable-storage bridge — stays in scp-runtime (tokio-coupled, node-only).
pub mod backend;
pub mod production_backend;
pub mod provider;
pub mod storage;
pub mod storage_adapter;

// Synchronous MLS state machine — re-exported from the wasm32-safe `scp-mls`
// crate under the historical module paths (ADR-057). Existing call sites that
// reference `crate::crypto::mls::{group, encrypt, ratchet, credential,
// key_package, error, wrapping_extension, epoch_grace}::*` resolve unchanged.
pub use scp_mls::{
    InMemoryMlsProvider, credential, encrypt, epoch_grace, error, group, key_package, ratchet,
    wrapping_extension,
};

// Re-export primary public API types for convenience (mirrors the pre-extraction
// flat re-exports so `crate::crypto::mls::{ScpCredential, MlsError, ...}` resolve).
pub use credential::ScpCredential;
pub use encrypt::DecryptedContent;
pub use error::MlsError;
pub use group::{
    AddMemberResult, RemoveMemberResult, SCP_CIPHERSUITE, ScpMlsGroup, add_member, create_group,
    create_group_with_wrapping_key, destroy_group, generate_key_package,
    generate_key_package_with_wrapping_key, join_group, remove_member,
};
pub use provider::MlsCryptoProvider;
pub use storage::{MlsStorageBridge, MlsStorageBridgeError, ScpMlsProvider, new_provider};
pub use wrapping_extension::{
    SCP_WRAPPING_KEY_EXTENSION_TYPE, extract_member_wrapping_key, extract_own_wrapping_key,
    extract_wrapping_key, find_leaf_index_by_did, leaf_node_params_with_wrapping_key,
    make_wrapping_key_extension, scp_capabilities_with_wrapping_key,
};
