//! The `scp-node` binary refuses two run modes at once, before it probes or
//! starts anything. `conflicting_modes` holds the rule; this test proves that
//! `main` calls it ahead of the `--health` probe and the mode dispatch.

#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Every pair of the three mode selectors, plus `SCP_NODE_SELF_HOST=1` standing
/// in for `--self-host`, exits 1 with the refusal, both with and without
/// `--health`.
///
/// With `--health`, a binary that lost the check probes a closed loopback port
/// and exits without the refusal. Without `--health`, it reaches the mode
/// dispatch: the relay-only cases start a relay on an ephemeral loopback port
/// and the `--self-host` cases start self-hosting from `SCP_STORAGE_PATH`, with
/// the NAT probe skipped and the DHT disabled so nothing leaves the machine.
/// Either way the stderr assertion or the 30-second deadline fails. The
/// storage assertion fails when the self-host path, or anything `main` runs
/// before the check, creates `SCP_STORAGE_PATH`.
#[test]
fn two_run_modes_exit_1_before_the_health_probe_and_the_mode_dispatch() {
    let cases: [(&[&str], Option<&str>); 5] = [
        (&["--relay-only", "--self-host"], None),
        (&["--relay-only"], Some("1")),
        (&["--relay-only", "--ephemeral"], None),
        (&["--self-host", "--ephemeral"], None),
        (&["--ephemeral"], Some("true")),
    ];
    for health in [true, false] {
        for (args, self_host_env) in cases {
            assert_refused(args, self_host_env, health);
        }
    }
}

/// Spawns `scp-node` with `args` (plus `--health` when `health`) and asserts it
/// exits 1 with the refusal and leaves `SCP_STORAGE_PATH` uncreated.
fn assert_refused(args: &[&str], self_host_env: Option<&str>, health: bool) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = tmp.path().join("node-storage");
    let mut command = Command::new(env!("CARGO_BIN_EXE_scp-node"));
    command
        .args(args)
        .current_dir(tmp.path())
        .env("SCP_STORAGE_PATH", &storage)
        .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
        .env("SCP_NODE_SELF_HOST_PORT", "0")
        .env("SCP_NODE_SELF_HOST_NO_NAT", "1")
        .env("SCP_NODE_SELF_HOST_PLAINTEXT", "1")
        .env("SCP_NODE_DHT_MODE", "disabled")
        .env_remove("SCP_NODE_SELF_HOST")
        .env_remove("SCP_RELAY_STORAGE_BACKEND")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if health {
        command.arg("--health");
    }
    if let Some(value) = self_host_env {
        command.env("SCP_NODE_SELF_HOST", value);
    }
    let case = format!("{args:?} health={health} SCP_NODE_SELF_HOST={self_host_env:?}");
    let mut child = command.spawn().expect("spawn scp-node");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{case}: scp-node did not exit within 30 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().expect("collect scp-node output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{case}: {stderr}");
    assert!(
        stderr.contains("each select a run mode; select exactly one."),
        "{case}: {stderr}"
    );
    assert!(
        !storage.exists(),
        "{case} created its storage directory before refusing"
    );
}

/// The error text `docs/guides/relay-operations.md` and `main.rs` tell an
/// operator to search a shipped full node's log for is the text the binary
/// logs: `main` logs the `NodeError` with `%e`, so its `Display` is what the
/// log holds, and the variant name `NoPreRotationBackend` is not in it.
#[test]
fn shipped_full_node_logs_the_documented_pre_rotation_error_text() {
    let logged = scp_node::NodeError::Identity(scp_identity::IdentityError::NoPreRotationBackend)
        .to_string();
    assert!(
        logged.starts_with("identity error: no production pre-rotation custody backend available"),
        "the documented log text drifted from NodeError's Display: {logged}"
    );
    assert!(
        !logged.contains("NoPreRotationBackend"),
        "the log now names the variant; update the operator docs: {logged}"
    );
}
