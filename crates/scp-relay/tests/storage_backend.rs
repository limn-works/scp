#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for storage backend selection in `scp-relay`.
//!
//! These tests exercise the binary's `SCP_RELAY_STORAGE_BACKEND` env-var
//! driven backend selection, verifying that:
//!
//! - `SQLite` is the default and persists across restarts (AC 1, 2, 3, 8)
//! - Invalid backend names produce a non-zero exit and descriptive error (AC 9)
//! - `postgres` without `SCP_RELAY_DATABASE_URL` produces a non-zero exit (AC 10)
//! - `s3` without `SCP_RELAY_S3_BUCKET` produces a non-zero exit (AC 6)

use std::process::Command;

/// Returns the path to the compiled `scp-relay` binary.
fn relay_bin() -> std::path::PathBuf {
    // `cargo test` sets this for integration tests in the same package.
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_scp-relay") {
        return std::path::PathBuf::from(path);
    }
    // Fallback: look in target/debug.
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // repo root
    path.push("target/debug/scp-relay");
    path
}

/// AC 9: An invalid backend value causes a non-zero exit with an error
/// message naming the valid options.
#[test]
fn invalid_backend_exits_with_error() {
    let output = Command::new(relay_bin())
        .env("SCP_RELAY_STORAGE_BACKEND", "banana")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to execute scp-relay");

    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid backend"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("banana"),
        "error should name the invalid value; got: {stderr}"
    );
    assert!(
        stderr.contains("sqlite"),
        "error should list valid options; got: {stderr}"
    );
    assert!(
        stderr.contains("memory"),
        "error should list valid options; got: {stderr}"
    );
}

/// AC 10: Selecting `postgres` without `SCP_RELAY_DATABASE_URL` exits with
/// a descriptive error.
#[test]
fn postgres_without_url_exits_with_error() {
    let output = Command::new(relay_bin())
        .env("SCP_RELAY_STORAGE_BACKEND", "postgres")
        .env_remove("SCP_RELAY_DATABASE_URL")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to execute scp-relay");

    assert!(
        !output.status.success(),
        "expected non-zero exit when postgres URL is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SCP_RELAY_DATABASE_URL"),
        "error should mention the required env var; got: {stderr}"
    );
}

/// AC 6: Selecting `s3` without `SCP_RELAY_S3_BUCKET` exits with a
/// descriptive error.
#[test]
fn s3_without_bucket_exits_with_error() {
    let output = Command::new(relay_bin())
        .env("SCP_RELAY_STORAGE_BACKEND", "s3")
        .env_remove("SCP_RELAY_S3_BUCKET")
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to execute scp-relay");

    assert!(
        !output.status.success(),
        "expected non-zero exit when S3 bucket is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SCP_RELAY_S3_BUCKET"),
        "error should mention the required env var; got: {stderr}"
    );
}

/// AC 8: `SQLite` blob persistence across reopens.
///
/// Verifies that blobs stored in an SQLite-backed `BlobStorageBackend`
/// survive closing and reopening the database — the same persistence
/// guarantee exercised when a relay restarts.
#[test]
fn sqlite_blob_persistence_across_reopens() {
    use scp_transport::native::storage::{BlobStorage, BlobStorageBackend};

    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmp.path().join("test-persistence.db");

    let routing_id = [0xAA; 32];
    let blob_id = [0xBB; 32];
    let blob_data = b"hello persistence test".to_vec();

    // --- First open: store a blob ---
    {
        let backend = BlobStorageBackend::sqlite(&db_path).expect("failed to open sqlite backend");

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let stored = backend
                .store(routing_id, blob_id, None, 3600, blob_data.clone())
                .await
                .expect("failed to store blob");

            assert_eq!(stored.blob, blob_data, "stored data should match");

            // Verify immediate retrieval.
            let retrieved = backend.get(&blob_id).await.expect("get failed");
            assert!(
                retrieved.is_some(),
                "blob should be retrievable immediately"
            );
            assert_eq!(retrieved.unwrap().blob, blob_data);
        });
    }
    // Backend dropped — database connection closed.

    // Verify the database file exists and is non-empty.
    assert!(db_path.exists(), "sqlite database file should exist");
    assert!(
        std::fs::metadata(&db_path).unwrap().len() > 0,
        "sqlite database should be non-empty"
    );

    // --- Second open: verify the blob persisted ---
    {
        let backend =
            BlobStorageBackend::sqlite(&db_path).expect("failed to reopen sqlite backend");

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let retrieved = backend
                .get(&blob_id)
                .await
                .expect("get failed after reopen");
            assert!(
                retrieved.is_some(),
                "blob should survive backend close and reopen"
            );
            assert_eq!(
                retrieved.unwrap().blob,
                blob_data,
                "persisted blob data should match original"
            );
        });
    }
}

/// AC 2 (default): When `SCP_RELAY_STORAGE_BACKEND` is not set, the relay
/// defaults to sqlite. Verify by starting the relay with a temp storage
/// path and confirming the sqlite DB file is created.
#[test]
fn default_backend_is_sqlite() {
    use std::io::Read;
    use std::time::Duration;

    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmp.path().join("default-backend.db");

    let mut child = Command::new(relay_bin())
        .env_remove("SCP_RELAY_STORAGE_BACKEND") // not set = default
        .env("SCP_RELAY_STORAGE_PATH", db_path.to_str().unwrap())
        .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
        .env("SCP_RELAY_LOG_FORMAT", "json")
        .env("RUST_LOG", "scp_relay=info,scp_transport=info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start scp-relay");

    // Read stderr in a background thread so kill doesn't lose buffered data.
    let stderr_handle = child.stderr.take().expect("no stderr");
    let output_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut reader = stderr_handle;
        let _ = reader.read_to_string(&mut buf);
        buf
    });

    // Wait for the relay to initialize by polling for the DB file.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut db_created = false;
    while std::time::Instant::now() < deadline {
        if db_path.exists() {
            db_created = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Kill the relay to release the stderr pipe.
    child.kill().ok();
    child.wait().ok();

    let output = output_thread.join().expect("output thread panicked");

    assert!(
        db_created,
        "sqlite database file should be created when using default backend; output: {output}"
    );

    // Verify the relay used sqlite (logged "using sqlite blob storage").
    assert!(
        output.contains("using sqlite blob storage"),
        "relay should have logged 'using sqlite blob storage'; output: {output}"
    );
}
