//! MLS (Messaging Layer Security) wrapper for SCP — node-only async bridge.
//!
//! The **synchronous** MLS state machine (`group`, `encrypt`, `ratchet`,
//! `credential`, `key_package`, `error`, `wrapping_extension`, `epoch_grace`,
//! and the `provider` module's `InMemoryMlsProvider`) lives in the wasm32-safe [`scp_mls`]
//! crate (ADR-057) so it can be shared by both the native node runtime and
//! in-browser SCP clients. `scp-runtime` call sites import those items from
//! `scp_mls` directly (no re-export shim — ADR-057 Amendment).
//!
//! This module keeps the tokio-coupled, node-only parts (`provider`,
//! `backend`, `production_backend`, `storage_adapter`). Every live MLS
//! provider is `scp_mls::InMemoryMlsProvider`; its state persists as a
//! snapshot blob (persistence spec §17.9.1).
//!
//! # Ciphersuite
//!
//! All groups use `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (ciphersuite 2,
//! §9.5; no ciphersuite negotiation). See ADR-001 for the rationale.
//!
//! See ADR-001 in `.docs/adrs/phase-1.md` for the MLS wrapper design and
//! ADR-057 for the `scp-mls` extraction.

// Runtime-coupled tests for `scp_mls::wrapping_extension` that exercise the
// node-only sender-key protocol (carved out of the moved file; ADR-057).
#[cfg(test)]
mod wrapping_extension_runtime_tests;

// The signer of a KeyPackage's `0xFF03` attestation, bound to the owner's
// resolved `#active` key, and the one mint path every native KeyPackage
// minter uses (§9.7.1).
pub mod attestation_signer;

// The async MLS provider (tokio-coupled, node-only). The backend and storage
// adapter it drives live in `scp_runtime_types::crypto::mls`.
pub mod provider;

// Shared two-party joined-pair bootstrap for provider-level unit tests (drives
// the REAL reserve → creator-add → sign → HPKE-seal → spawn-from-Welcome join
// path). Test-only: its sole callers are in-crate `#[cfg(test)]` fixtures.
#[cfg(test)]
pub(crate) mod two_party_test_support;

pub use provider::NodeMlsFactory;
