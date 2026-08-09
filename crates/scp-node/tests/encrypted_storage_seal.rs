#![allow(clippy::missing_const_for_fn)]
//! Structural tests for the `EncryptedStorage` seal and `Node` ZST invariant
//! (ADR-052 / spec §17.5).
//!
//! Three invariants are verified here:
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
//!
//! 3. **Positive controls for the ADR-052 §AC-9 compile-fail assertions.** The
//!    negative half of §AC-9 — that a plaintext `FilesystemStorage` cannot
//!    reach `Node::start` or `ProtocolRepository::new` — is asserted by
//!    `compile_fail,E0277` doctests on those two constructors
//!    (`crates/scp-node/src/config.rs`,
//!    `crates/scp-runtime/src/store/mod.rs`), because rustdoc is the
//!    toolchain's built-in compile-fail harness and needs no new dependency or
//!    committed `.stderr` fixture to drift.
//!
//!    A bare `compile_fail` is only as strong as its control: it passes for
//!    *any* compile error, including a typo. The functions below are that
//!    control. They call the **same** constructors over the **same** backend
//!    wrapped in `EncryptingAdapter` and must compile, which pins the doctest
//!    failures to the missing `EncryptedStorage` impl rather than to an
//!    unrelated breakage. They live here rather than only in doctests so every
//!    `cargo test` / `cargo nextest` / `cargo clippy --all-targets` lane
//!    type-checks them, not just CI's doctest job.

use scp_core::store::ProtocolRepository;
use scp_identity::DidMethod;
use scp_node::{Node, NodeConfig};
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::filesystem::FilesystemStorage;
use scp_platform::traits::KeyCustody;
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
// ADR-052 §AC-9 positive controls
//
// Each function is the exact counterpart of a `compile_fail,E0277` doctest,
// differing ONLY in that the plaintext backend is wrapped in
// `EncryptingAdapter`. If one of these ever stops compiling, the paired
// doctest's "failure" has stopped being attributable to the seal and the
// §AC-9 guarantee is no longer proven.
// ---------------------------------------------------------------------------

/// Counterpart of the `Node::start` compile-fail doctest.
///
/// `EncryptingAdapter<FilesystemStorage>` satisfies the sealed
/// `EncryptedStorage` bound, so the production constructor accepts it. The
/// doctest asserts the bare `FilesystemStorage` form does not compile.
#[allow(dead_code)]
fn _assert_encrypted_filesystem_reaches_production_node_start<K, D>(
    config: NodeConfig<K, D, EncryptingAdapter<FilesystemStorage>>,
) where
    K: KeyCustody + 'static,
    D: DidMethod + 'static,
{
    let _fut = Node::start(config);
}

/// Counterpart of the `ProtocolRepository::new` compile-fail doctest.
///
/// Same backend, same constructor — only the `EncryptingAdapter` wrap differs
/// from the form the doctest proves cannot compile.
#[allow(dead_code)]
fn _assert_encrypted_filesystem_reaches_production_repository_new(
    storage: EncryptingAdapter<FilesystemStorage>,
) {
    let _repo = ProtocolRepository::new(storage);
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
