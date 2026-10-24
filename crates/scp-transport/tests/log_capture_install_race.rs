//! The push sender tests' log capture (`src/relay/log_capture.rs`) loses no
//! event from a callsite another thread first reaches while the capture's
//! global subscriber is being installed.
//!
//! tracing-core caches each callsite's interest the first time the callsite is
//! reached. A callsite first reached after the level filter has opened but
//! before the global dispatcher is readable caches `Interest::never`, and the
//! capture never sees that callsite again. The global subscriber can be
//! installed only once per process, so the parent test runs the race in fresh
//! child processes of this test binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../src/relay/log_capture.rs"]
mod log_capture;

use std::process::Command;
use std::sync::Barrier;

use log_capture::LogCapture;

/// Set in a child process's environment to make `install_race_child` run.
const CHILD_ENV: &str = "SCP_LOG_CAPTURE_INSTALL_RACE_CHILD";

/// Child processes the parent runs; each is one installation race.
const RUNS: usize = 64;

/// Defines a spinner function with its own `trace!` callsite. Each spinner
/// reaches its callsite in a loop from before the installation starts, so it
/// registers the callsite at the first moment the level filter lets it
/// through. Once the global dispatcher is set it installs a capture on its own
/// thread, reaches the same callsite once more, and returns whether that event
/// reached the capture.
macro_rules! spinners {
    ($($name:ident = $index:literal),+ $(,)?) => {
        $(
            fn $name(start: &Barrier) -> bool {
                start.wait();
                let mut capture: Option<LogCapture> = None;
                loop {
                    let captured = capture.is_some();
                    tracing::trace!(spinner = $index, captured, "spinner callsite");
                    if let Some(capture) = &capture {
                        let marker = format!("spinner={} captured=true", $index);
                        return capture.contents().contains(&marker);
                    }
                    if tracing::dispatcher::has_been_set() {
                        capture = Some(LogCapture::install(|_| true));
                    }
                    std::hint::spin_loop();
                }
            }
        )+
        const SPINNERS: &[fn(&Barrier) -> bool] = &[$($name),+];
    };
}

spinners!(
    spinner_0 = 0,
    spinner_1 = 1,
    spinner_2 = 2,
    spinner_3 = 3,
    spinner_4 = 4,
    spinner_5 = 5,
    spinner_6 = 6,
    spinner_7 = 7,
);

/// One installation race; does nothing unless the parent set [`CHILD_ENV`].
#[test]
fn install_race_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let start = Barrier::new(SPINNERS.len() + 1);
    let lost: Vec<usize> = std::thread::scope(|scope| {
        let handles: Vec<_> = SPINNERS
            .iter()
            .map(|spinner| scope.spawn(|| spinner(&start)))
            .collect();
        start.wait();
        let _capture = LogCapture::install(|_| true);
        handles
            .into_iter()
            .enumerate()
            .filter_map(|(index, handle)| (!handle.join().unwrap()).then_some(index))
            .collect()
    });
    assert!(
        lost.is_empty(),
        "spinners whose event the capture lost: {lost:?}"
    );
}

#[test]
fn no_callsite_reached_during_installation_is_lost_to_the_capture() {
    let exe = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    for run in 0..RUNS {
        let output = Command::new(&exe)
            .args([
                "--exact",
                "install_race_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        if !output.status.success() {
            failures.push(format!(
                "run {run}: {}",
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .chain(String::from_utf8_lossy(&output.stderr).lines())
                    .find(|line| line.contains("spinners whose event"))
                    .unwrap_or("child failed without the lost-spinner message")
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {RUNS} installation races lost events:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
