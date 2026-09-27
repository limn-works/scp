//! A persistent `scp-node` rejects every configuration value it reads before
//! it writes anything, and opens its blob store only after its own storage
//! checks pass.
//!
//! `run_full_node_persistent` in `src/main.rs` reads `SCP_NODE_DHT_MODE` and
//! checks `SCP_RELAY_STORAGE_BACKEND` through
//! `scp_transport::startup::check_storage_selection_from_env` first, before it
//! creates its storage directory, its root key file, either `SQLCipher`
//! database, or the blob store. It validates the storage path next, and opens
//! the blob store through `scp_transport::startup::storage_from_env` last. The
//! relay binary's twin of the backend property lives in
//! `crates/scp-relay/tests/storage_backend.rs`.
//!
//! Job rust-test in `.github/workflows/ci.yml` runs this file at default
//! features, and job rust-test-optional-features runs it again with
//! `cloud-blobs`, which reaches the other half of each cloud-backend case.

#![allow(clippy::expect_used)]

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Output};

/// The `SCP_RELAY_STORAGE_BACKEND` values the persistent full node must
/// reject: the two cloud backends, and on Unix a value that is not valid UTF-8.
/// `--self-host` rejects only the two cloud backends, which
/// `self_host_rejects_a_cloud_backend_before_writing_storage` checks.
///
/// The non-UTF-8 value is a value the operator set, so it must be rejected as
/// unknown rather than read as unset, which would select `sqlite`.
fn rejected_backend_values() -> Vec<OsString> {
    let mut values = vec![OsString::from("postgres"), OsString::from("s3")];
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        values.push(OsString::from_vec(b"sq\xfflite".to_vec()));
    }
    values
}

/// Returns the path to the compiled `scp-node` binary.
///
/// Compile-time `env!` keeps the path correct under `cargo nextest run`, which
/// does not re-export `CARGO_BIN_EXE_*` into the test's runtime environment.
fn node_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_scp-node"))
}

/// Runs a persistent `scp-node` in `cwd` with `storage_dir` as its node
/// storage and `blob_db` as its sqlite blob path, plus `extra` variables.
fn run_node(cwd: &Path, storage_dir: &Path, blob_db: &Path, extra: &[(&str, &OsStr)]) -> Output {
    let mut command = Command::new(node_bin());
    command
        .current_dir(cwd)
        .env("SCP_NODE_DOMAIN", "example.com")
        .env("SCP_NODE_BIND_ADDR", "127.0.0.1:0")
        .env("SCP_STORAGE_PATH", storage_dir)
        .env("SCP_RELAY_STORAGE_PATH", blob_db)
        .env_remove("SCP_RELAY_STORAGE_BACKEND")
        .env_remove("SCP_NODE_DHT_MODE")
        .env_remove("SCP_RELAY_DATABASE_URL")
        .env_remove("SCP_RELAY_S3_BUCKET")
        .env_remove("SCP_STORAGE_KEY")
        .env_remove("RUST_LOG");
    for (key, value) in extra {
        command.env(key, value);
    }
    command.output().expect("failed to execute scp-node")
}

/// `postgres` and `s3` fail on every build: a default build compiled neither
/// arm and names the `cloud-blobs` feature, and a `cloud-blobs` build finds no
/// `SCP_RELAY_DATABASE_URL` or `SCP_RELAY_S3_BUCKET`. A value that is not
/// valid UTF-8 names no backend. In every case the node exits non-zero and the
/// storage directory it was given does not exist afterwards, so it wrote no
/// `.key` file and opened no database.
#[test]
fn a_rejected_blob_backend_writes_no_storage_before_exiting() {
    for value in rejected_backend_values() {
        let backend = value.to_string_lossy();
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage_dir = tmp.path().join("node-storage");
        let blob_db = tmp.path().join("blobs.db");

        let output = run_node(
            tmp.path(),
            &storage_dir,
            &blob_db,
            &[("SCP_RELAY_STORAGE_BACKEND", value.as_os_str())],
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "a rejected {backend} backend must exit non-zero; stderr: {stderr}"
        );
        assert!(
            stderr.contains(&*backend),
            "the rejection names the requested backend; stderr: {stderr}"
        );
        assert!(
            !storage_dir.exists(),
            "a rejected {backend} backend must create no storage directory, key \
             file, or database; found {}",
            storage_dir.display()
        );
    }
}

/// A mistyped `SCP_NODE_DHT_MODE`, and `disabled`, which only `--self-host`
/// accepts, exit non-zero before the node writes its storage directory or its
/// sqlite blob database.
#[test]
fn a_rejected_dht_mode_writes_no_storage_before_exiting() {
    for mode in ["memroy", "disabled"] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage_dir = tmp.path().join("node-storage");
        let blob_db = tmp.path().join("blobs.db");

        let output = run_node(
            tmp.path(),
            &storage_dir,
            &blob_db,
            &[("SCP_NODE_DHT_MODE", OsStr::new(mode))],
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "SCP_NODE_DHT_MODE={mode} must exit non-zero; stderr: {stderr}"
        );
        assert!(
            !storage_dir.exists(),
            "SCP_NODE_DHT_MODE={mode} must create no storage directory, key \
             file, or database; found {}",
            storage_dir.display()
        );
        assert!(
            !blob_db.exists(),
            "SCP_NODE_DHT_MODE={mode} must create no blob database; found {}",
            blob_db.display()
        );
    }
}

/// A storage path the node cannot create exits non-zero before the default
/// `sqlite` blob backend opens, so no blob database is left behind.
#[test]
fn an_unusable_storage_path_opens_no_blob_database() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A regular file where the storage directory's parent should be makes
    // `create_dir_all` fail.
    let not_a_dir = tmp.path().join("not-a-dir");
    std::fs::write(&not_a_dir, b"file").expect("write blocking file");
    let storage_dir = not_a_dir.join("node-storage");
    let blob_db = tmp.path().join("blobs.db");

    let output = run_node(tmp.path(), &storage_dir, &blob_db, &[]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an unusable storage path must exit non-zero; stderr: {stderr}"
    );
    assert!(
        stderr.contains("storage"),
        "the failure names the storage path; stderr: {stderr}"
    );
    assert!(
        !blob_db.exists(),
        "an unusable storage path must open no blob database; found {}",
        blob_db.display()
    );
}

/// `--self-host` opens only `SQLite`, so `SCP_RELAY_STORAGE_BACKEND=postgres`
/// or `=s3` exits non-zero, names the value, and leaves no storage directory,
/// instead of serving from a `SQLite` store the operator did not select.
///
/// A regression would start a server that never exits, so the child is killed
/// after 30 seconds and the test fails on the missing exit.
#[test]
fn self_host_rejects_a_cloud_backend_before_writing_storage() {
    for value in [OsString::from("postgres"), OsString::from("s3")] {
        let backend = value.to_string_lossy();
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage_dir = tmp.path().join("node-storage");
        let mut child = Command::new(node_bin())
            .arg("--self-host")
            .current_dir(tmp.path())
            .env("SCP_STORAGE_PATH", &storage_dir)
            .env("SCP_RELAY_STORAGE_BACKEND", &value)
            .env("SCP_NODE_DHT_MODE", "disabled")
            .env("SCP_NODE_SELF_HOST_NO_NAT", "1")
            .env("SCP_NODE_SELF_HOST_PORT", "0")
            .env_remove("RUST_LOG")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn scp-node --self-host");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let output = child.wait_with_output().expect("collect stderr");
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            status.is_some_and(|s| !s.success()),
            "--self-host with SCP_RELAY_STORAGE_BACKEND={backend} must exit \
             non-zero; status {status:?}, stderr: {stderr}"
        );
        assert!(
            stderr.contains(&format!("SCP_RELAY_STORAGE_BACKEND='{backend}'")),
            "the rejection names the requested backend; stderr: {stderr}"
        );
        assert!(
            !storage_dir.exists(),
            "a rejected {backend} backend must create no storage directory; found {}",
            storage_dir.display()
        );
    }
}

/// A `--features cloud-blobs` build of this binary compiled both cloud arms,
/// so `postgres` and `s3` fail on the variable each backend requires and never
/// on "not compiled into this binary".
///
/// Every other test in this file chooses its expected outcome from the build,
/// so without this test a `cloud-blobs` list that stopped enabling
/// `scp-transport/postgres-blob` or `scp-transport/s3-blob` would leave the
/// `cloud-blobs` lane green while the binary told operators to rebuild with the
/// flag they had just passed.
#[cfg(feature = "cloud-blobs")]
#[test]
fn the_cloud_blobs_feature_compiles_both_cloud_backends() {
    for (backend, required) in [
        ("postgres", "SCP_RELAY_DATABASE_URL"),
        ("s3", "SCP_RELAY_S3_BUCKET"),
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let output = run_node(
            tmp.path(),
            &tmp.path().join("node-storage"),
            &tmp.path().join("blobs.db"),
            &[("SCP_RELAY_STORAGE_BACKEND", OsStr::new(backend))],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("not compiled"),
            "a cloud-blobs build must compile the {backend} arm; stderr: {stderr}"
        );
        assert!(
            stderr.contains(required),
            "a cloud-blobs build must reach the {backend} arm and name {required}; \
             stderr: {stderr}"
        );
    }
}
