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

pub use provider::NodeMlsFactory;
pub use storage::{MlsStorageBridge, MlsStorageBridgeError, ScpMlsProvider};

/// Single source of truth for the **testing-only** DID-method carve-out used by
/// the MLS identity checks.
///
/// Returns `true` when `did` uses one of the two mock DID-method prefixes —
/// `did:test:` or `did:key:` — that the MLS identity-validation paths accept in
/// place of resolving a real `did:dht:z…` DID. This is a POSITIVE WHITELIST: it
/// names the exact prefixes the legacy mock-based test suite uses, and nothing
/// else. Its sole current caller is
/// [`NodeMlsFactory::validate_creator_identity`](provider::NodeMlsFactory::validate_creator_identity);
/// it exists as one definition so that any additional MLS identity carve-out
/// routes through the same predicate rather than re-spelling it and drifting.
///
/// # Security — MUST NOT be reachable in shipped artifacts
///
/// The whole function is gated behind `#[cfg(any(test, feature = "testing"))]`, so
/// it is COMPILED OUT of every shipped (no-`testing`) production build. The
/// `scripts/check-shipped-feature-graph.sh` G1 gate proves the `testing` feature
/// never enters a shipped artifact's feature graph, so this carve-out cannot exist
/// on a production path. Production identity validation therefore requires a real,
/// resolvable `did:dht:z…` DID.
///
/// `did:web:` and `did:dht:` are NEVER exempt by this predicate: `did:dht:` is the
/// real production method (validated on its own path, not via this carve-out), and
/// `did:web:` has no testing exemption whatsoever.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn is_testing_exempt_did(did: &str) -> bool {
    did.starts_with("did:test:") || did.starts_with("did:key:")
}
