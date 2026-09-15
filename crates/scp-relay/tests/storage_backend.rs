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
//!
//! `scp-transport`'s `postgres-blob` and `s3-blob` features gate the `postgres`
//! and `s3` arms. This crate's off-by-default `cloud-blobs` feature is one way
//! to enable that pair: cargo unifies `scp-transport`'s features across every
//! package one invocation builds, so another package in the same build enables
//! the pair too, and the arms then compile with `cloud-blobs` off. Each test
//! below that drives one of those two values
//! therefore asserts one of two outcomes, chosen by [`backend_is_compiled`]:
//! when the arm exists the relay reaches it and reports the env var the backend
//! needs; when it does not, the relay reports that the arm is not compiled in
//! and names the feature to rebuild with. Branching inside the test rather than
//! gating the whole test out keeps every test running in every configuration
//! CI builds.

use std::process::Command;

/// Reports whether this build compiled the `storage_from_env` arm that
/// constructs `name`.
///
/// This reads `scp-transport`'s resolved features rather than `scp-relay`'s
/// `cloud-blobs`, because the two can disagree. `cloud-blobs` is one way to
/// turn on `scp-transport/postgres-blob`, and cargo unifies `scp-transport`'s
/// features across every package a single invocation builds, so another package
/// in the same build can enable that feature while `scp-relay/cloud-blobs`
/// stays off. `scp_transport::startup::backend_is_compiled` reads the `cfg!`
/// flag that gates the arm, and this test binary links the same `scp-transport`
/// the relay binary links, so the answer here is the relay's behaviour rather
/// than a proxy for it.
///
/// It reads that flag rather than parsing `VALID_BACKENDS`, which is the
/// constant the relay prints. Predicting the message out of the constant the
/// message is assembled from would make `invalid_backend_exits_with_error`
/// below compare `VALID_BACKENDS` against itself, and that comparison stays
/// green through the exact regression that test's doc comment names: a
/// `VALID_BACKENDS` reverted to the hardcoded `"sqlite, redb, postgres, s3,
/// memory"` while the arms stay `cfg`-gated.
fn backend_is_compiled(name: &str) -> bool {
    scp_transport::startup::backend_is_compiled(name)
}

/// Returns the path to the compiled `scp-relay` binary.
///
/// Resolves the compile-time `CARGO_BIN_EXE_scp-relay` variable Cargo bakes into
/// integration-test builds for a binary in the same package. Using compile-time
/// `env!` (not a runtime `std::env::var` lookup) keeps the path correct under
/// `cargo test`, `cargo nextest run`, relocated target dirs
/// (`CARGO_TARGET_DIR`/shared-target), and git worktrees alike — `cargo nextest`
/// does not re-export `CARGO_BIN_EXE_*` into the test's runtime environment.
fn relay_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_scp-relay"))
}

/// AC 9: An invalid backend value causes a non-zero exit with an error
/// message naming the valid options.
///
/// The options list must name exactly the arms this build compiled. Before
/// `postgres-blob` and `s3-blob` moved behind `cloud-blobs`, the message read
/// its list from a hardcoded constant, so a default build rejected `postgres`
/// and then listed `postgres` among the valid options.
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

    for backend in ["postgres", "s3"] {
        assert_eq!(
            stderr.contains(backend),
            backend_is_compiled(backend),
            "the options list must offer '{backend}' exactly when this build \
             compiled its arm; got: {stderr}"
        );
    }
}

/// AC 10: Selecting `postgres` without `SCP_RELAY_DATABASE_URL` exits with
/// a descriptive error — on a build that compiled the postgres arm. A default
/// build compiled no postgres arm, and exits naming the feature that would.
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
    if backend_is_compiled("postgres") {
        assert!(
            stderr.contains("SCP_RELAY_DATABASE_URL"),
            "error should mention the required env var; got: {stderr}"
        );
    } else {
        assert!(
            stderr.contains("'postgres' is not compiled into this binary"),
            "a default build should say the postgres arm is absent; got: {stderr}"
        );
        assert!(
            stderr.contains(&format!("--features {}", binary_feature("postgres"))),
            "error should name the feature that compiles the arm; got: {stderr}"
        );
    }
}

/// AC 6: Selecting `s3` without `SCP_RELAY_S3_BUCKET` exits with a
/// descriptive error — on a build that compiled the s3 arm. A default build
/// compiled no s3 arm, and exits naming the feature that would.
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
    if backend_is_compiled("s3") {
        assert!(
            stderr.contains("SCP_RELAY_S3_BUCKET"),
            "error should mention the required env var; got: {stderr}"
        );
    } else {
        assert!(
            stderr.contains("'s3' is not compiled into this binary"),
            "a default build should say the s3 arm is absent; got: {stderr}"
        );
        assert!(
            stderr.contains(&format!("--features {}", binary_feature("s3"))),
            "error should name the feature that compiles the arm; got: {stderr}"
        );
    }
}

/// The feature name the rejection message tells an operator to pass to
/// `cargo build` is a feature both binaries declare.
///
/// `BACKENDS` in `crates/scp-transport/src/startup.rs` carries that name in its
/// `binary_feature` column, `crates/scp-relay/Cargo.toml` and
/// `crates/scp-node/Cargo.toml` each declare it in their `[features]` table,
/// and until this test existed no check compared the three. The four scanning
/// tests beside that table all read `include_str!("startup.rs")`, so each one
/// pins the `scp-transport` feature a backend needs and none of them opens
/// either manifest. A rename carried through one manifest and not the column,
/// or through the column and neither manifest, left every one of them green
/// while a default-build relay sent an operator to a `--features` value cargo
/// rejects with "none of the selected packages contains this feature".
///
/// This test reads both manifests, because the gating is one invariant across
/// two crates rather than two independent ones: cargo unifies `scp-transport`'s
/// features across every package a single invocation builds, so a `scp-node`
/// that stopped gating `postgres-blob` would re-resolve it into `scp-relay`,
/// which is the reason `crates/scp-relay/Cargo.toml` states beside its own
/// declaration.
#[test]
fn the_binary_feature_the_message_names_is_declared_by_both_manifests() {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();

    for backend in ["postgres", "s3"] {
        let feature = binary_feature(backend);
        for package in ["scp-relay", "scp-node"] {
            let path = crates_dir.join(package).join("Cargo.toml");
            let manifest = std::fs::read_to_string(&path).unwrap_or_default();
            assert!(
                !manifest.is_empty(),
                "failed to read {} while checking that it declares '{feature}'",
                path.display()
            );
            assert!(
                features_table_declares(&manifest, feature),
                "the rejection message for '{backend}' names                  `--features {feature}`, and the [features] table of {} declares                  no such feature",
                path.display()
            );
        }
    }
}

/// The `scp-node` / `scp-relay` feature that compiles `backend`'s arm of
/// `storage_from_env`, read out of the table the rejection message is built
/// from.
///
/// Panics when the table gives `backend` no binary feature, which is the
/// answer for `sqlite`, `redb` and `memory`. Every caller here passes
/// `postgres` or `s3`.
fn binary_feature(backend: &str) -> &'static str {
    let feature = scp_transport::startup::backend_binary_feature(backend);
    assert!(
        feature.is_some(),
        "the BACKENDS table gives '{backend}' no binary feature, so no message          can tell an operator what to rebuild with"
    );
    feature.unwrap_or_default()
}

/// Reports whether the `[features]` table of a `Cargo.toml` declares `feature`.
///
/// Reads the lines between the `[features]` header and the next table header,
/// and compares the text left of the first `=` against `feature`. A comment
/// line and a continuation line inside an array value both fail that
/// comparison. An absent `[features]` header leaves nothing to iterate, so this
/// returns `false` and the caller's assertion names the manifest.
fn features_table_declares(manifest: &str, feature: &str) -> bool {
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[features]")
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .any(|line| {
            line.split('=')
                .next()
                .is_some_and(|key| key.trim() == feature)
        })
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
    //
    // The deadline bounds how long this test waits; it states nothing about
    // the relay, because the assertions below still require that a relay
    // created its sqlite file and logged `using sqlite blob storage`. A longer
    // wait therefore weakens nothing. Under `cargo nextest run --workspace`
    // this binary starts alongside ~11,000 other tests: a 10-second deadline
    // expired twice on one 2026-08-17 local run, and once more on a pass over
    // 11019 tests where a debug-profile relay binary competed for CPU with
    // every other test binary and reached 10.062s without writing its file.
    // Both reruns passed, and this test passes on its own in 1.4 to 2.9
    // seconds, so 10 seconds measured machine load rather than relay behavior.
    // One minute leaves headroom under that load and still fails within one
    // test-run budget when a relay genuinely never starts.
    let deadline = std::time::Instant::now() + Duration::from_mins(1);
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
