//! A `scp-node` rejects `SCP_RELAY_STORAGE_BACKEND` values `postgres` and `s3`
//! that it cannot serve (a build without `cloud-blobs`, or a missing URL or
//! bucket) instead of opening another blob store. `--self-host`, which opens
//! only `SQLite`, and `--ephemeral`, which keeps blobs in memory, reject both in
//! every build that has the mode.

#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Returns the path to the compiled `scp-node` binary.
fn node_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_scp-node"))
}

/// Runs `command` and returns its output, killing the child and failing the
/// test when it has not exited after 30 seconds.
///
/// The caller expects `scp-node` to reject its configuration and exit. A
/// regression that falls back to another store starts a node that serves
/// forever, and this deadline turns that hang into a failed assertion.
fn output_within_deadline(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn scp-node");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("scp-node did not exit within 30 seconds, so it is serving a fallback store");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("collect scp-node output")
}

/// A persistent full node and a `--relay-only` node each exit non-zero on
/// `postgres` without `SCP_RELAY_DATABASE_URL` and on `s3` without
/// `SCP_RELAY_S3_BUCKET`, in either case, and open no `SQLite` blob store in
/// their place. A build that compiled the arm names the missing variable; a
/// build without `cloud-blobs` names the feature, and the full node exits
/// before it creates its storage directory, its storage key, or its root and
/// custody stores.
///
/// `--relay-only` reads the backend in `scp-node`'s own `run_relay_only`, not
/// through `scp_transport::startup::start_relay_from_env`, so the `scp-relay`
/// binary's test does not cover that path.
///
/// Which of the two errors to expect is read from the `scp-transport` this test
/// links, and not from this package's own `cloud-blobs` feature: cargo unifies
/// `scp-transport`'s features across every package one invocation builds, so
/// `scp-relay`'s `cloud-blobs` alone compiles the arms into this binary too.
/// This package's own `cloud-blobs` feature decides one case: a build with it
/// on must list both arms, so the test fails when that feature stops enabling
/// `scp-transport/postgres-blob` or `scp-transport/s3-blob`.
#[test]
fn a_cloud_backend_fails_closed() {
    let compiled = scp_transport::startup::valid_backends();
    for backend in ["postgres", "s3"] {
        assert!(
            !cfg!(feature = "cloud-blobs") || compiled.split(", ").any(|name| name == backend),
            "scp-node's cloud-blobs feature is on, but this build lists only {compiled} and not '{backend}'"
        );
    }
    let cases = [
        ("postgres", "postgres", "SCP_RELAY_DATABASE_URL"),
        ("postgres", "POSTGRES", "SCP_RELAY_DATABASE_URL"),
        ("s3", "s3", "SCP_RELAY_S3_BUCKET"),
        ("s3", "S3", "SCP_RELAY_S3_BUCKET"),
    ];
    for mode in [&[][..], &["--relay-only"][..]] {
        for (backend, value, required_var) in cases {
            let tmp = tempfile::tempdir().expect("tempdir");
            let blob_db = tmp.path().join("blobs.db");
            let node_storage = tmp.path().join("node-storage");
            let output = output_within_deadline(
                Command::new(node_bin())
                    .args(mode)
                    .current_dir(tmp.path())
                    .env("SCP_NODE_DOMAIN", "example.com")
                    .env("SCP_NODE_BIND_ADDR", "127.0.0.1:0")
                    .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
                    .env("SCP_STORAGE_PATH", &node_storage)
                    .env("SCP_RELAY_STORAGE_PATH", &blob_db)
                    .env("SCP_RELAY_STORAGE_BACKEND", value)
                    .env_remove(required_var)
                    .env_remove("SCP_NODE_DHT_MODE")
                    .env_remove("SCP_STORAGE_KEY")
                    .env_remove("RUST_LOG"),
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            let case = format!("{value} {mode:?}");
            assert!(!output.status.success(), "{case}: {stderr}");
            if compiled.split(", ").any(|name| name == backend) {
                assert!(stderr.contains(required_var), "{case}: {stderr}");
            } else {
                assert!(
                    stderr.contains(&format!("'{backend}' is not compiled into this binary")),
                    "{case}: {stderr}"
                );
                assert!(
                    stderr.contains("--features cloud-blobs"),
                    "{case}: {stderr}"
                );
                assert!(
                    !node_storage.exists(),
                    "{case} created {} before rejecting the backend",
                    node_storage.display()
                );
            }
            assert!(!blob_db.exists(), "{case} opened {}", blob_db.display());
        }
    }
}

/// `--self-host` exits non-zero on `postgres` and `s3`, in either case, and
/// names the value, instead of serving from a `SQLite` store the operator did
/// not select. A build with the `testing` feature also runs `--ephemeral`, which
/// exits the same way instead of keeping blobs in memory.
#[test]
fn a_fixed_store_mode_rejects_a_cloud_backend() {
    let mut modes = vec![("--self-host", "in SQLite under its storage directory")];
    if cfg!(feature = "testing") {
        modes.push(("--ephemeral", "in memory"));
    }
    for (flag, store) in modes {
        for backend in ["postgres", "s3", "POSTGRES", "S3"] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let output = output_within_deadline(
                Command::new(node_bin())
                    .arg(flag)
                    .current_dir(tmp.path())
                    .env("SCP_NODE_DOMAIN", "example.com")
                    .env("SCP_NODE_BIND_ADDR", "127.0.0.1:0")
                    .env("SCP_STORAGE_PATH", tmp.path().join("node-storage"))
                    .env("SCP_RELAY_STORAGE_BACKEND", backend)
                    .env("SCP_NODE_DHT_MODE", "disabled")
                    .env("SCP_NODE_SELF_HOST_NO_NAT", "1")
                    .env("SCP_NODE_SELF_HOST_PORT", "0")
                    .env_remove("RUST_LOG"),
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{flag} {backend}: {stderr}");
            assert!(
                stderr.contains(&format!(
                    "{flag} stores blobs {store} and cannot use SCP_RELAY_STORAGE_BACKEND='{backend}'"
                )),
                "{flag} {backend}: {stderr}"
            );
        }
    }
}
