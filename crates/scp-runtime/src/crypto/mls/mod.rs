//! MLS (Messaging Layer Security) wrapper for SCP — node-only async bridge.
//!
//! The **synchronous** MLS state machine (`group`, `encrypt`, `ratchet`,
//! `credential`, `key_package`, `error`, `wrapping_extension`, `epoch_grace`,
//! and the `InMemoryMlsProvider` alias) lives in the wasm32-safe [`scp_mls`]
//! crate (ADR-057) so it can be shared by both the native node runtime and
//! in-browser SCP clients. `scp-runtime` call sites import those items from
//! `scp_mls` directly (no re-export shim — ADR-057 Amendment).
//!
//! This module keeps the **async durable-storage bridge** (`storage`,
//! `provider`, `backend`, `production_backend`, `storage_adapter`) — the
//! `block_in_place`/`ScpMlsProvider<S>` parts that are tokio-coupled and
//! node-only.
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

// Shared two-party joined-pair bootstrap for provider-level unit tests (drives
// the REAL reserve → creator-add → sign → HPKE-seal → spawn-from-Welcome join
// path). Test-only: its sole callers are in-crate `#[cfg(test)]` fixtures.
#[cfg(test)]
pub(crate) mod two_party_test_support;

pub use provider::MlsCryptoProvider;
pub use storage::{MlsStorageBridge, MlsStorageBridgeError, ScpMlsProvider};
