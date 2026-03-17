//! MLS (Messaging Layer Security) wrapper for SCP.
//!
//! This module wraps `OpenMLS` to provide SCP-specific MLS group operations.
//! Every SCP context maps to one MLS group. The wrapper exposes SCP-specific
//! lifecycle operations and hides `OpenMLS` internals behind a clean interface.
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
//! - [`storage`] — `StorageProvider` bridge to scp-platform storage adapters.
//! - [`error`] — MLS-specific error types.
//!
//! # Phase 1 Scope
//!
//! Phase 1 implements group lifecycle (create, add, remove, destroy) with
//! in-memory storage. Encrypt/decrypt (SCP-004) and ratcheting/key packages
//! (SCP-005) are separate stories.
//!
//! See ADR-001 in `.docs/adrs/phase-1.md` for the full MLS wrapper design.

pub mod credential;
pub mod encrypt;
pub mod epoch_grace;
pub mod error;
pub mod group;
pub mod key_package;
pub mod provider;
pub mod ratchet;
pub mod storage;
pub mod wrapping_extension;

// Re-export primary public API types for convenience.
pub use credential::ScpCredential;
pub use encrypt::DecryptedContent;
pub use error::MlsError;
pub use group::{
    AddMemberResult, RemoveMemberResult, SCP_CIPHERSUITE, ScpMlsGroup, add_member, create_group,
    create_group_with_wrapping_key, destroy_group, generate_key_package,
    generate_key_package_with_wrapping_key, join_group, remove_member,
};
pub use provider::MlsCryptoProvider;
pub use storage::{
    InMemoryMlsProvider, MlsStorageBridge, MlsStorageBridgeError, ScpMlsProvider, new_provider,
};
pub use wrapping_extension::{
    SCP_WRAPPING_KEY_EXTENSION_TYPE, extract_member_wrapping_key, extract_own_wrapping_key,
    extract_wrapping_key, find_leaf_index_by_did, leaf_node_params_with_wrapping_key,
    make_wrapping_key_extension, scp_capabilities_with_wrapping_key,
};
