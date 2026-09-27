//! A persistent `scp-node` rejects a blob backend selection it cannot
//! construct before it creates its storage directory, its root key file, or
//! either `SQLCipher` database.
//!
//! `run_full_node_persistent` in `src/main.rs` resolves
//! `SCP_RELAY_STORAGE_BACKEND` through `scp_transport::startup::storage_from_env`
//! first. That function exits 1 when the value names a backend this build did
//! not compile or omits a variable the backend requires, and a configuration
//! error must leave no key material behind. The relay binary's twin of this
//! property lives in `crates/scp-relay/tests/storage_backend.rs`.

#![allow(clippy::expect_used)]

use std::process::Command;

/// Returns the path to the compiled `scp-node` binary.
///
/// Compile-time `env!` keeps the path correct under `cargo nextest run`, which
/// does not re-export `CARGO_BIN_EXE_*` into the test's runtime environment.
fn node_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_scp-node"))
}

/// `postgres` fails on every build: a default build compiled no postgres arm
/// and names the `cloud-blobs` feature, and a `cloud-blobs` build finds no
/// `SCP_RELAY_DATABASE_URL`. In both cases the node exits non-zero and the
/// storage directory it was given does not exist afterwards, so it wrote no
/// `.key` file and opened no database.
#[test]
fn a_rejected_blob_backend_writes_no_storage_before_exiting() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_dir = tmp.path().join("node-storage");

    let output = Command::new(node_bin())
        .current_dir(tmp.path())
        .env("SCP_NODE_DOMAIN", "example.com")
        .env("SCP_NODE_BIND_ADDR", "127.0.0.1:0")
        .env("SCP_STORAGE_PATH", &storage_dir)
        .env("SCP_RELAY_STORAGE_BACKEND", "postgres")
        .env_remove("SCP_RELAY_DATABASE_URL")
        .env_remove("SCP_STORAGE_KEY")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to execute scp-node");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a rejected blob backend must exit non-zero; stderr: {stderr}"
    );
    assert!(
        stderr.contains("postgres"),
        "the rejection names the requested backend; stderr: {stderr}"
    );
    assert!(
        !storage_dir.exists(),
        "a rejected blob backend must create no storage directory, key file, \
         or database; found {}",
        storage_dir.display()
    );
}
