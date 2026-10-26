#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for storage backend selection in `scp-relay`.
//!
//! These tests exercise the binary's `SCP_RELAY_STORAGE_BACKEND` env-var
//! driven backend selection, verifying that:
//!
//! - an unset or empty `SCP_RELAY_STORAGE_BACKEND` produces a non-zero exit
//!   naming that variable and SCP-CAPSEL-8000, because persistence spec §17.7
//!   and §17.17.1 forbid a default backend
//! - `sqlite` with an unset, empty, or relative `SCP_RELAY_STORAGE_PATH`
//!   produces a non-zero exit naming that variable and opens no store
//! - an operator who names `sqlite` with an absolute path gets `SQLite`, and
//!   stored blobs survive a reopen (AC 1, 3, 8)
//! - Invalid backend names produce a non-zero exit and descriptive error (AC 9)
//! - `postgres` without `SCP_RELAY_DATABASE_URL` produces a non-zero exit (AC 10)
//! - `s3` without `SCP_RELAY_S3_BUCKET` produces a non-zero exit (AC 6)
//! - a build without `cloud-blobs` rejects `postgres` and `s3` instead, names
//!   the feature, and opens no other store

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Runs `command` and returns its output, killing the child and failing the
/// test when it has not exited after 30 seconds.
///
/// The caller expects `scp-relay` to reject its configuration and exit. A
/// regression that falls back to another store starts a relay that serves
/// forever, and this deadline turns that hang into a failed assertion.
fn output_within_deadline(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn scp-relay");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("scp-relay did not exit within 30 seconds, so it is serving a fallback store");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("collect scp-relay output")
}

/// Asserts that `scp-relay` exits non-zero on `SCP_RELAY_STORAGE_BACKEND=backend`,
/// in lower and in upper case, with `required_var` unset, and opens no `SQLite`
/// store in its place.
///
/// The expected error follows what the binary compiled, read from the
/// `scp-transport` this test links, and not from this package's own
/// `cloud-blobs` feature: cargo unifies `scp-transport`'s features across every
/// package one invocation builds, so `scp-node`'s `cloud-blobs` alone compiles
/// the arm into this binary too. A build with the arm names `required_var`; a
/// build without it names the missing `cloud-blobs` feature. This package's
/// own `cloud-blobs` feature decides one case: a build with it on must list
/// the arm, so the test fails when that feature stops enabling
/// `scp-transport/postgres-blob` or `scp-transport/s3-blob`.
fn assert_cloud_backend_fails_closed(backend: &str, required_var: &str) {
    let valid = scp_transport::startup::valid_backends();
    let compiled = valid.split(", ").any(|name| name == backend);
    assert!(
        !cfg!(feature = "cloud-blobs") || compiled,
        "scp-relay's cloud-blobs feature is on, but this build lists only {valid} and not '{backend}'"
    );
    for value in [backend.to_owned(), backend.to_uppercase()] {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tmp.path().join("must-not-exist.db");
        let output = output_within_deadline(
            relay_command()
                .env("SCP_RELAY_STORAGE_BACKEND", &value)
                .env("SCP_RELAY_STORAGE_PATH", &db_path)
                .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
                .env_remove(required_var)
                .env_remove("RUST_LOG"),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{value}: {stderr}");
        if compiled {
            assert!(stderr.contains(required_var), "{value}: {stderr}");
        } else {
            assert!(
                stderr.contains(&format!("'{backend}' is not compiled into this binary")),
                "{value}: {stderr}"
            );
            assert!(
                stderr.contains("--features cloud-blobs"),
                "{value}: {stderr}"
            );
        }
        assert!(!db_path.exists(), "{value} opened {}", db_path.display());
    }
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

/// The relay URL every test but `unset_or_empty_relay_url_exits_with_error`
/// sets, so each reaches the configuration it tests.
const RELAY_URL: &str = "wss://relay.example/scp/v1";

/// A command that runs `scp-relay` with `SCP_RELAY_URL` set to [`RELAY_URL`]
/// and `SCP_RELAY_PUSH_PLATFORMS=none`. The relay refuses to start without
/// either. The URL and push tests below override or remove one of them.
fn relay_command() -> Command {
    let mut command = Command::new(relay_bin());
    command
        .env("SCP_RELAY_URL", RELAY_URL)
        .env("SCP_RELAY_PUSH_PLATFORMS", "none");
    command
}

/// An unset, empty, or whitespace `SCP_RELAY_URL` makes the relay exit 1 with
/// an error naming the variable, before it opens a store. The relay derives
/// its reserved push routing ID from that URL (§10.7.1), so the variable has
/// no default.
#[test]
fn unset_or_empty_relay_url_exits_with_error() {
    for value in [None, Some(""), Some("  ")] {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tmp.path().join("must-not-exist.db");
        let mut command = relay_command();
        command
            .current_dir(tmp.path())
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_STORAGE_PATH", &db_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env_remove("RUST_LOG");
        match value {
            Some(v) => command.env("SCP_RELAY_URL", v),
            None => command.env_remove("SCP_RELAY_URL"),
        };
        let output = output_within_deadline(&mut command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{value:?}: {stderr}");
        assert!(
            stderr.contains("SCP_RELAY_URL must be set to a non-empty value"),
            "{value:?}: {stderr}"
        );
        assert!(!db_path.exists(), "{value:?} opened a store");
    }
}

/// PUSH-012: an unset or blank `SCP_RELAY_PUSH_PLATFORMS` makes the relay exit
/// 1 naming the variable and SCP-CAPSEL-8000 (push selection has no default),
/// before it opens its blob store.
#[test]
fn unset_push_platforms_exits_with_capsel_8000() {
    for value in [None, Some(""), Some(" ")] {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tmp.path().join("must-not-exist.db");
        let mut command = relay_command();
        command
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_STORAGE_PATH", &db_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env_remove("RUST_LOG");
        match value {
            Some(v) => command.env("SCP_RELAY_PUSH_PLATFORMS", v),
            None => command.env_remove("SCP_RELAY_PUSH_PLATFORMS"),
        };
        let output = output_within_deadline(&mut command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{value:?}: {stderr}");
        assert!(
            stderr.contains("SCP_RELAY_PUSH_PLATFORMS is unset or empty"),
            "{value:?}: {stderr}"
        );
        assert!(stderr.contains("SCP-CAPSEL-8000"), "{value:?}: {stderr}");
        assert!(!db_path.exists(), "{value:?} opened {}", db_path.display());
    }
}

/// PUSH-023: `scp-relay` serves no `.well-known/scp` document, so it refuses
/// `webpush` in `SCP_RELAY_PUSH_PLATFORMS`: it exits 1 naming the variable and
/// SCP-CAPSEL-8001, though every `WebPush` variable is set, and opens neither
/// the push store nor the blob store.
#[test]
fn webpush_is_refused_with_capsel_8001() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmp.path().join("must-not-exist.db");
    let push_path = tmp.path().join("push-must-not-exist.db");
    for value in ["webpush", "fcm,webpush"] {
        let mut command = relay_command();
        command
            .env("SCP_RELAY_PUSH_PLATFORMS", value)
            .env("SCP_RELAY_PUSH_STORE", "sqlite")
            .env("SCP_RELAY_PUSH_STORE_PATH", &push_path)
            .env(
                "SCP_RELAY_WEBPUSH_VAPID_KEY_PATH",
                tmp.path().join("vapid.pem"),
            )
            .env(
                "SCP_RELAY_WEBPUSH_VAPID_SUBJECT",
                "mailto:operator@relay.example",
            )
            .env("SCP_RELAY_WEBPUSH_NAT64_PREFIXES", "none")
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_STORAGE_PATH", &db_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env_remove("RUST_LOG");
        let output = output_within_deadline(&mut command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{value}: {stderr}");
        assert!(
            stderr.contains("SCP_RELAY_PUSH_PLATFORMS lists webpush"),
            "{value}: {stderr}"
        );
        assert!(stderr.contains("SCP-CAPSEL-8001"), "{value}: {stderr}");
        assert!(!db_path.exists(), "{value} opened {}", db_path.display());
        assert!(
            !push_path.exists(),
            "{value} opened {}",
            push_path.display()
        );
    }
}

/// PUSH-012: a push platform with a partial configuration makes the relay
/// exit 1 naming the first missing variable, and opens neither the push store
/// nor the blob store.
#[test]
fn partial_push_configuration_exits_naming_the_variable() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmp.path().join("must-not-exist.db");
    let push_path = tmp.path().join("push-must-not-exist.db");
    let cases: [(&[(&str, &str)], &str); 3] = [
        (
            &[("SCP_RELAY_PUSH_PLATFORMS", "apns")],
            "SCP_RELAY_PUSH_STORE",
        ),
        (
            &[
                ("SCP_RELAY_PUSH_PLATFORMS", "apns"),
                ("SCP_RELAY_PUSH_STORE", "memory"),
            ],
            "SCP_RELAY_PUSH_STORE",
        ),
        (
            &[
                ("SCP_RELAY_PUSH_PLATFORMS", "fcm"),
                ("SCP_RELAY_PUSH_STORE", "sqlite"),
            ],
            "SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH",
        ),
    ];
    for (vars, named) in cases {
        let mut command = relay_command();
        command
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_STORAGE_PATH", &db_path)
            .env("SCP_RELAY_PUSH_STORE_PATH", &push_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env_remove("SCP_RELAY_PUSH_STORE")
            .env_remove("SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH")
            .env_remove("RUST_LOG");
        for (var, value) in vars {
            command.env(var, value);
        }
        let output = output_within_deadline(&mut command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{vars:?}: {stderr}");
        assert!(stderr.contains(named), "{vars:?}: {stderr}");
        assert!(!db_path.exists(), "{vars:?} opened {}", db_path.display());
        assert!(
            !push_path.exists(),
            "{vars:?} opened {}",
            push_path.display()
        );
    }
}

/// An unset `SCP_RELAY_STORAGE_BACKEND`, and an empty or whitespace one, each
/// make the relay exit 1 with an error naming the variable, SCP-CAPSEL-8000
/// (persistence spec §17.17.1, selection is mandatory), and the valid values,
/// and the relay opens no store.
///
/// Restoring the `sqlite` default for an unset variable makes the relay open
/// `SCP_RELAY_STORAGE_PATH` and serve, so the deadline or the exit assertion
/// fails.
#[test]
fn unset_or_empty_backend_exits_with_capsel_8000() {
    for value in [None, Some(""), Some("  ")] {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tmp.path().join("must-not-exist.db");
        let mut command = relay_command();
        command
            .current_dir(tmp.path())
            .env("SCP_RELAY_STORAGE_PATH", &db_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env_remove("RUST_LOG");
        match value {
            Some(v) => command.env("SCP_RELAY_STORAGE_BACKEND", v),
            None => command.env_remove("SCP_RELAY_STORAGE_BACKEND"),
        };
        let output = output_within_deadline(&mut command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{value:?}: {stderr}");
        assert!(
            stderr.contains("SCP_RELAY_STORAGE_BACKEND is unset or empty"),
            "{value:?}: {stderr}"
        );
        assert!(stderr.contains("SCP-CAPSEL-8000"), "{value:?}: {stderr}");
        assert!(
            stderr.contains(&scp_transport::startup::valid_backends()),
            "{value:?}: {stderr}"
        );
        assert!(!db_path.exists(), "{value:?} opened {}", db_path.display());
    }
}

/// `sqlite` with `SCP_RELAY_STORAGE_PATH` unset, empty, or relative makes the
/// relay exit 1 with an error naming that variable, and the relay creates no
/// database in its working directory.
///
/// Restoring the `./scp-relay.db` default makes the unset case open that file
/// in the working directory and serve, so the deadline or the exit assertion
/// fails.
#[test]
fn sqlite_without_an_absolute_path_exits_with_error() {
    for (path, expected) in [
        (None, "requires SCP_RELAY_STORAGE_PATH"),
        (Some(""), "requires SCP_RELAY_STORAGE_PATH"),
        (Some("./scp-relay.db"), "is a relative path"),
        (Some("scp-relay.db"), "is a relative path"),
    ] {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        let mut command = relay_command();
        command
            .current_dir(tmp.path())
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env_remove("RUST_LOG");
        match path {
            Some(p) => command.env("SCP_RELAY_STORAGE_PATH", p),
            None => command.env_remove("SCP_RELAY_STORAGE_PATH"),
        };
        let output = output_within_deadline(&mut command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{path:?}: {stderr}");
        assert!(
            stderr.contains("SCP_RELAY_STORAGE_PATH"),
            "{path:?}: {stderr}"
        );
        assert!(stderr.contains(expected), "{path:?}: {stderr}");
        let created: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read tempdir")
            .collect();
        assert!(
            created.is_empty(),
            "{path:?} created {created:?} in the working directory"
        );
    }
}

/// AC 9: An invalid backend value causes a non-zero exit with an error
/// message naming the valid options.
#[test]
fn invalid_backend_exits_with_error() {
    let output = relay_command()
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
/// an error naming that variable, or, in a build without `cloud-blobs`, with
/// an error naming the feature.
#[test]
fn postgres_without_url_exits_with_error() {
    assert_cloud_backend_fails_closed("postgres", "SCP_RELAY_DATABASE_URL");
}

/// AC 6: Selecting `s3` without `SCP_RELAY_S3_BUCKET` exits with an error
/// naming that variable, or, in a build without `cloud-blobs`, with an error
/// naming the feature.
#[test]
fn s3_without_bucket_exits_with_error() {
    assert_cloud_backend_fails_closed("s3", "SCP_RELAY_S3_BUCKET");
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

/// AC 2 (explicit selection): `SCP_RELAY_STORAGE_BACKEND=sqlite` with an
/// absolute `SCP_RELAY_STORAGE_PATH` starts a relay on `SQLite`. Verify by
/// starting the relay with a temp storage path and waiting for it to log
/// `using sqlite blob storage`, then confirming the sqlite DB file exists. The
/// backend has no default, so this test names it.
///
/// The relay logs that line only after the store has opened, and it creates
/// the file when the open begins. The test therefore waits for the line, not
/// for the file: a relay killed once the file appears can die before the open
/// returns and logs.
#[test]
fn explicit_sqlite_backend_starts() {
    const OPENED: &str = "using sqlite blob storage";

    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let db_path = tmp.path().join("explicit-backend.db");

    let (opened, output) = run_until_logged(
        relay_command()
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_STORAGE_PATH", db_path.to_str().unwrap()),
        OPENED,
    );

    assert!(
        opened,
        "relay should have logged '{OPENED}' within one minute; output: {output}"
    );
    assert!(
        db_path.exists(),
        "sqlite database file should be created when the operator names sqlite; output: {output}"
    );
}

/// Starts `command` with a loopback bind address, JSON logs at info level, and
/// stderr piped, waits until a log line contains `needle` or the relay exits,
/// then kills the relay. Returns whether the line appeared and everything the
/// relay wrote to stderr.
fn run_until_logged(command: &mut Command, needle: &str) -> (bool, String) {
    use std::io::BufRead;
    use std::sync::mpsc::{self, RecvTimeoutError};

    let mut child = command
        .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
        .env("SCP_RELAY_LOG_FORMAT", "json")
        .env("RUST_LOG", "scp_relay=info,scp_transport=info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start scp-relay");

    // Forward stderr line by line as it arrives. The channel disconnects when
    // the relay closes stderr, which it does only by exiting.
    let stderr_handle = child.stderr.take().expect("no stderr");
    let (lines_tx, lines_rx) = mpsc::channel::<String>();
    let reader_thread = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr_handle).lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });

    // The deadline bounds how long this test waits; it states nothing about
    // the relay, because each caller still asserts on the line and on the
    // files the relay created. A longer wait therefore weakens nothing. Under
    // `cargo nextest run --workspace` this binary starts alongside ~11,000
    // other tests: a 10-second deadline expired twice on one 2026-08-17 local
    // run, and once more on a pass over 11019 tests where a debug-profile
    // relay binary competed for CPU with every other test binary and reached
    // 10.062s without writing its file. Both reruns passed, and a relay starts
    // on its own in 1.4 to 2.9 seconds, so 10 seconds measured machine load
    // rather than relay behavior. One minute leaves headroom under that load
    // and still fails within one test-run budget when a relay never starts.
    let deadline = Instant::now() + Duration::from_mins(1);
    let mut output = String::new();
    let mut seen = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match lines_rx.recv_timeout(remaining) {
            Ok(line) => {
                seen = line.contains(needle);
                output.push_str(&line);
                output.push('\n');
                if seen {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }

    // Stop the relay, which closes stderr and ends the reader thread.
    child.kill().ok();
    child.wait().ok();
    output.extend(lines_rx.iter().map(|line| line + "\n"));
    reader_thread.join().expect("stderr reader thread panicked");
    (seen, output)
}

/// Writes `contents` to `name` in `dir` with owner-only permissions, as the
/// relay requires of a credential file.
#[cfg(unix)]
fn write_owner_only(dir: &std::path::Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write credential file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict credential file");
    path
}

/// A version-0 PKCS#8 P-256 private key as a .p8 PEM file, built at run time
/// so no key file is committed. The scalar is fixed: the relay only parses
/// the key at startup and these tests send no wake signal.
#[cfg(unix)]
fn apns_p8_pem() -> String {
    use base64::Engine as _;
    // The P-256 `AlgorithmIdentifier` (id-ecPublicKey, prime256v1).
    const P256_ALGORITHM_ID: [u8; 19] = [
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07,
    ];
    let mut ec = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
    ec.extend_from_slice(&[0x11; 32]);
    let mut body = vec![0x02, 0x01, 0x00, 0x30, 0x13];
    body.extend_from_slice(&P256_ALGORITHM_ID);
    body.push(0x04);
    body.push(u8::try_from(ec.len()).unwrap());
    body.extend_from_slice(&ec);
    let mut der = vec![0x30, u8::try_from(body.len()).unwrap()];
    der.extend_from_slice(&body);
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{encoded}\n-----END PRIVATE KEY-----\n")
}

/// A relay command with `SCP_RELAY_PUSH_PLATFORMS=apns`, an APNs key file in
/// `dir`, the `sqlite` push store at `push_path`, and a `memory` blob store.
#[cfg(unix)]
fn apns_relay_command(dir: &std::path::Path, push_path: &std::path::Path) -> Command {
    let key_path = write_owner_only(dir, "AuthKey.p8", apns_p8_pem().as_bytes());
    let mut command = relay_command();
    command
        .current_dir(dir)
        .env("SCP_RELAY_STORAGE_BACKEND", "memory")
        .env("SCP_RELAY_PUSH_PLATFORMS", "apns")
        .env("SCP_RELAY_PUSH_STORE", "sqlite")
        .env("SCP_RELAY_PUSH_STORE_PATH", push_path)
        .env("SCP_RELAY_APNS_KEY_PATH", key_path)
        .env("SCP_RELAY_APNS_KEY_ID", "ABC123DEFG")
        .env("SCP_RELAY_APNS_TEAM_ID", "TEAM123456")
        .env("SCP_RELAY_APNS_TOPIC", "works.limn.app")
        .env("SCP_RELAY_APNS_ENVIRONMENT", "sandbox");
    command
}

/// PUSH-012 criterion 6: the shipped `scp-relay` binary accepts
/// `SCP_RELAY_PUSH_STORE=sqlite`. With `apns` listed it opens the SQLite push
/// store at `SCP_RELAY_PUSH_STORE_PATH`, logs that push is enabled, and
/// listens; the file it created opens as a push store after the relay stops.
#[cfg(unix)]
#[test]
fn sqlite_push_store_starts_the_relay_with_push_enabled() {
    const ENABLED: &str = "push: enabled with the sqlite push store";
    const LISTENING: &str = "relay listening";
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let push_path = tmp.path().join("push.sqlite");

    let (listening, output) =
        run_until_logged(&mut apns_relay_command(tmp.path(), &push_path), LISTENING);

    assert!(
        listening,
        "relay should have logged '{LISTENING}'; output: {output}"
    );
    assert!(
        output.contains(ENABLED),
        "relay did not report push enabled; output: {output}"
    );
    assert!(
        push_path.exists(),
        "the relay did not create its push store at {}; output: {output}",
        push_path.display()
    );
    scp_transport::relay::push_store::PushRegistrationStore::open_sqlite(
        &push_path,
        scp_transport::relay::push_store::PushStoreAtRest::Unkeyed,
    )
    .expect("the file the relay created opens as a push store");
}

/// A push store path whose parent is a regular file makes the relay exit 1
/// with the typed store-open refusal under SCP-CAPSEL-8001, and the relay never
/// reports push as enabled or starts listening.
#[cfg(unix)]
#[test]
fn unopenable_push_store_exits_with_capsel_8001() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let blocker = tmp.path().join("this-is-a-file");
    std::fs::write(&blocker, b"not a directory").expect("write blocker file");
    let push_path = blocker.join("push.sqlite");

    let output = output_within_deadline(
        apns_relay_command(tmp.path(), &push_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env("RUST_LOG", "scp_relay=info,scp_transport=info"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("cannot open the push store"), "{stderr}");
    assert!(stderr.contains("SCP-CAPSEL-8001"), "{stderr}");
    assert!(!stderr.contains("push: enabled"), "{stderr}");
    assert!(!stderr.contains("relay listening"), "{stderr}");
}

/// A `sqlite` store that cannot open makes the relay exit 1 with the
/// `StoreOpen` error, and the relay never logs `using sqlite blob storage`
/// (persistence spec §17.17.1 SCP-CAPSEL-8001: a failed selection is
/// terminal). A log line naming a backend the relay never opened tells an
/// operator reading the log that the store is up when it is not.
///
/// The path's parent component is a regular file, so the directory and the
/// database cannot be created.
#[test]
fn sqlite_store_that_cannot_open_exits_without_logging_the_backend() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let blocker = tmp.path().join("this-is-a-file");
    std::fs::write(&blocker, b"not a directory").expect("write blocker file");
    let db_path = blocker.join("relay.db");

    let output = output_within_deadline(
        relay_command()
            .current_dir(tmp.path())
            .env("SCP_RELAY_STORAGE_BACKEND", "sqlite")
            .env("SCP_RELAY_STORAGE_PATH", &db_path)
            .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
            .env("RUST_LOG", "scp_relay=info,scp_transport=info"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("failed to open the sqlite blob store"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("using sqlite blob storage"),
        "the relay logged a backend it never opened: {stderr}"
    );
}
