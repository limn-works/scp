//! A `scp-node` built without `cloud-blobs` rejects `SCP_RELAY_STORAGE_BACKEND`
//! values `postgres` and `s3` instead of opening another blob store, and
//! `--self-host`, which opens only `SQLite`, rejects both in every build.

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

/// A persistent full node built without `cloud-blobs` exits non-zero on
/// `postgres` and `s3`, names the feature, and opens no `SQLite` blob store.
#[cfg(not(feature = "cloud-blobs"))]
#[test]
fn a_cloud_backend_without_cloud_blobs_is_rejected_naming_the_feature() {
    for backend in ["postgres", "s3"] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let blob_db = tmp.path().join("blobs.db");
        let output = output_within_deadline(
            Command::new(node_bin())
                .current_dir(tmp.path())
                .env("SCP_NODE_DOMAIN", "example.com")
                .env("SCP_NODE_BIND_ADDR", "127.0.0.1:0")
                .env("SCP_STORAGE_PATH", tmp.path().join("node-storage"))
                .env("SCP_RELAY_STORAGE_PATH", &blob_db)
                .env("SCP_RELAY_STORAGE_BACKEND", backend)
                .env_remove("SCP_NODE_DHT_MODE")
                .env_remove("SCP_STORAGE_KEY")
                .env_remove("RUST_LOG"),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{backend}: {stderr}");
        assert!(
            stderr.contains(&format!("'{backend}' is not compiled into this binary")),
            "{backend}: {stderr}"
        );
        assert!(
            stderr.contains("--features cloud-blobs"),
            "{backend}: {stderr}"
        );
        assert!(!blob_db.exists(), "{backend} opened {}", blob_db.display());
    }
}

/// `--self-host` exits non-zero on `postgres` and `s3` and names the value,
/// instead of serving from a `SQLite` store the operator did not select.
#[test]
fn self_host_rejects_a_cloud_backend() {
    for backend in ["postgres", "s3"] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let output = output_within_deadline(
            Command::new(node_bin())
                .arg("--self-host")
                .current_dir(tmp.path())
                .env("SCP_STORAGE_PATH", tmp.path().join("node-storage"))
                .env("SCP_RELAY_STORAGE_BACKEND", backend)
                .env("SCP_NODE_DHT_MODE", "disabled")
                .env("SCP_NODE_SELF_HOST_NO_NAT", "1")
                .env("SCP_NODE_SELF_HOST_PORT", "0")
                .env_remove("RUST_LOG"),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{backend}: {stderr}");
        assert!(
            stderr.contains(&format!("SCP_RELAY_STORAGE_BACKEND='{backend}'")),
            "{backend}: {stderr}"
        );
    }
}
