//! The `scp-node` binary refuses two run modes at once, before it probes or
//! starts anything. `conflicting_modes` holds the rule; this test proves that
//! `main` calls it ahead of the `--health` probe and the mode dispatch.

#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Every pair of the three mode selectors, plus `SCP_NODE_SELF_HOST=1` standing
/// in for `--self-host`, exits 1 with the refusal. Each case also passes
/// `--health`, so a binary that lost the check probes a closed loopback port and
/// exits without starting a node or publishing to the DHT; the stderr assertion
/// then fails, because the probe prints no refusal.
#[test]
fn two_run_modes_exit_1_before_the_health_probe() {
    let cases: [(&[&str], Option<&str>); 5] = [
        (&["--relay-only", "--self-host"], None),
        (&["--relay-only"], Some("1")),
        (&["--relay-only", "--ephemeral"], None),
        (&["--self-host", "--ephemeral"], None),
        (&["--ephemeral"], Some("true")),
    ];
    for (args, self_host_env) in cases {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut command = Command::new(env!("CARGO_BIN_EXE_scp-node"));
        command
            .args(args)
            .arg("--health")
            .current_dir(tmp.path())
            .env("SCP_STORAGE_PATH", tmp.path().join("node-storage"))
            .env_remove("SCP_NODE_SELF_HOST")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(value) = self_host_env {
            command.env("SCP_NODE_SELF_HOST", value);
        }
        let mut child = command.spawn().expect("spawn scp-node");
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().expect("try_wait").is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?} {self_host_env:?}: scp-node did not exit within 30 seconds");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().expect("collect scp-node output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let case = format!("{args:?} SCP_NODE_SELF_HOST={self_host_env:?}");
        assert_eq!(output.status.code(), Some(1), "{case}: {stderr}");
        assert!(
            stderr.contains("each select a run mode; select exactly one."),
            "{case}: {stderr}"
        );
        assert!(
            !tmp.path().join("node-storage").exists(),
            "{case} created its storage directory before refusing"
        );
    }
}
