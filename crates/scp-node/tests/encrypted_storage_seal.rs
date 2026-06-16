#![allow(clippy::missing_const_for_fn)]
//! Structural tests for the `EncryptedStorage` seal and `Node` ZST invariant
//! (ADR-052 / spec §17.5).
//!
//! Two invariants are verified here:
//!
//! 1. **`Node` is a zero-sized type.** `Node` is used exclusively as a
//!    namespace for associated functions (`Node::start`,
//!    `Node::start_for_testing`). A non-ZST would indicate a regression to a
//!    stateful instantiated type, violating ADR-052 §AC-4 /
//!    construction.md M5.
//!
//! 2. **`EncryptedStorage` extends `Storage` (supertrait check).** This is the
//!    structural property that makes `where S: EncryptedStorage` a strictly
//!    stronger bound than `where S: Storage` alone, forming the
//!    encryption-at-rest guarantee enforced by `Node::start`
//!    (`crates/scp-platform/src/encrypted.rs`). The assertion is expressed as
//!    a function that fails to *compile* — not just to run — if
//!    `EncryptedStorage: Storage` supertrait is ever severed. Unlike a comment
//!    or a doc-note, a compile failure is machine-verified on every CI run.

use scp_node::Node;
use scp_platform::{EncryptedStorage, Storage};

// ---------------------------------------------------------------------------
// Compile-time supertrait assertion
// ---------------------------------------------------------------------------

/// Proves that `EncryptedStorage: Storage`.
///
/// If the `Storage` supertrait on `EncryptedStorage` is ever removed, the
/// inner call `require_storage::<S>()` will fail to compile because
/// `S: EncryptedStorage` alone will no longer imply `S: Storage`. This
/// function is intentionally never called — it is purely a compile-time check.
#[allow(dead_code)]
fn _assert_encrypted_storage_extends_storage<S: EncryptedStorage>() {
    const fn require_storage<T: Storage>() {}
    require_storage::<S>();
}

// ---------------------------------------------------------------------------
// Runtime structural assertions
// ---------------------------------------------------------------------------

/// `Node` must be a zero-sized type (ADR-052 §AC-4, construction.md M5).
///
/// `Node` is the public namespace ZST for `Node::start` and
/// `Node::start_for_testing`. A non-zero size indicates a regression to a
/// stateful struct — which would violate the unified construction pattern and
/// expose internal state that should be private to `ApplicationNode`.
#[test]
fn node_is_zero_sized() {
    assert_eq!(
        std::mem::size_of::<Node>(),
        0,
        "Node must be a ZST (namespace for associated fns, ADR-052 §AC-4). \
         A non-zero size indicates a regression to a stateful type."
    );
}
