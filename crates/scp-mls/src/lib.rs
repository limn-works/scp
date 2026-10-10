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
//! orchestration) or `scp-identity` (tokio-coupled custody/DHT). Every live
//! MLS provider is the in-memory provider here; the runtime persists its state
//! as a snapshot blob (persistence spec §17.9.1).
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
//! - [`convergent_timestamp`] — Authenticated convergent committer timestamp
//!   carried in the MLS AAD (ADR-057).
//! - [`encrypt`] — Application-message encrypt/decrypt over the MLS group.
//! - [`ratchet`] — Update proposals and MLS message serialization.
//! - [`key_package`] — Single-use `KeyPackage` buffer management.
//! - [`lifetime`] — `KeyPackage` `Lifetime` minting/validation via the injected
//!   [`scp_clock::Clock`] (ADR-057 Prereq-1).
//! - [`wrapping_extension`] — `scp_wrapping_key` `LeafNode` extension helpers.
//! - [`keypackage_attestation`] — `scp_keypackage_attestation` (`0xFF03`)
//!   `LeafNode` extension: the DID-to-leaf `KeyPackage` attestation type + wire
//!   format (§9.5.2, §9.7.1).
//! - [`context_extension`] — `scp_context_params` `group_context` extension
//!   helpers (§5.13.3, finding FFI-02).
//! - [`epoch_grace`] — Epoch grace-window store (forward-secrecy bound).
//! - [`provider`] — The in-memory MLS provider, which zeroizes its storage on
//!   drop and refuses to store the MLS signer (persistence spec §17.9).
//! - [`error`] — MLS-specific error types.
//!
//! See ADR-001 in `.docs/adrs/phase-1.md` for the MLS wrapper design and
//! ADR-057 for the `scp-mls` extraction.

// The crate holds the MLS signer, `destroy_group`, and the zeroizing provider;
// no unsafe code may enter it.
#![forbid(unsafe_code)]

pub mod context_extension;
pub mod convergent_timestamp;
pub mod credential;
pub mod encrypt;
pub mod epoch_grace;
pub mod error;
pub mod group;
pub mod key_package;
pub mod keypackage_attestation;
pub mod lifetime;
pub mod provider;
pub mod ratchet;
pub mod snapshot;
pub mod wrapping_extension;

// Re-export primary public API types for convenience.
pub use convergent_timestamp::{
    CONVERGENT_TIMESTAMP_AAD_LEN, CONVERGENT_TIMESTAMP_AAD_MAGIC, CONVERGENT_TIMESTAMP_AAD_VERSION,
    decode_convergent_timestamp_aad, encode_convergent_timestamp_aad,
};
pub use credential::ScpCredential;
pub use encrypt::{DecryptedContent, InboundChange};
pub use error::MlsError;
pub use keypackage_attestation::{
    AttestationLeafGroundTruth, AttestationResolutionVerifyError, AttestationTrigger,
    AttestationVerifyError, KeyPackageAttestation, MAX_ATTESTATION_KEY_RESOLUTION_STALENESS,
    MAX_KEYPACKAGE_ATTESTATION_LIFETIME, SCP_KEYPACKAGE_ATTESTATION_DOMAIN,
    SCP_KEYPACKAGE_ATTESTATION_EXTENSION_TYPE, scp_capabilities_with_keypackage_attestation,
    verify_attestation_with_resolution,
};

// The MLS signing key pair appears in this crate's public op signatures
// (`generate_key_package` returns it; `join_group` consumes it). Re-export it so
// consumers — notably the in-browser participant driver (ADR-057) — can name
// the type without taking a direct dependency on `openmls_basic_credential`.
pub use context_extension::{
    extract_context_params, group_context_extensions, make_context_params_extension,
    scp_capabilities_with_context_params,
};
pub use group::{
    AddMemberResult, RemoveMemberResult, SCP_CIPHERSUITE, ScpMlsGroup, add_member,
    add_member_with_convergent_timestamp, create_group, create_group_with_context,
    create_group_with_wrapping_key, destroy_group, generate_key_package,
    generate_key_package_with_context_params, generate_key_package_with_wrapping_key, join_group,
    key_package_in_did, key_package_in_wrapping_key, remove_member,
};
pub use lifetime::{
    KEY_PACKAGE_LIFETIME_MARGIN_SECS, KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS,
    KEY_PACKAGE_LIFETIME_SECS, KEY_PACKAGE_MIN_NOT_BEFORE_AGE_SECS,
    KEY_PACKAGE_MIN_REMAINING_LIFETIME_SECS, key_package_lifetime, validate_key_package_lifetime,
    validate_key_package_lifetime_for_add,
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

// The in-memory MLS provider holds all key material in process memory,
// zeroizes its storage values on drop, and refuses to store the MLS signer
// (persistence spec §17.9). The native runtime snapshots it to durable storage
// and an in-browser client snapshots it to `IndexedDB`, both out of band
// (§17.9.1). It lives in `scp-mls` so the sync MLS machine is self-contained
// (ADR-057).
pub use provider::{InMemoryMlsProvider, InMemoryMlsStorage, InMemoryMlsStorageError};
