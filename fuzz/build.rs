//! Fails this crate's build when the compiler it resolved is not the one
//! `fuzz/rust-toolchain.toml` names.
//!
//! WHY THIS EXISTS. `fuzz/rust-toolchain.toml` names a nightly, and rustup applies it to
//! any cargo command run inside `fuzz/` — unless `RUSTUP_TOOLCHAIN` is set in the
//! environment, which overrides a toolchain file entirely. A shell carrying that variable
//! compiles this crate on the root pin, and the first symptom is
//! `error: the option 'Z' is only accepted on the nightly compiler`, emitted by rustc
//! against a command line the developer never wrote. This build script reports the cause
//! instead, and names the variable.
//!
//! It also gives `.github/workflows/ci.yml`'s `fuzz-build` job something to assert. That
//! job runs `cargo check` with `working-directory: fuzz` and would succeed on stable,
//! because `cargo check` passes no `-Z` flag, so without this script a broken directory
//! override would reach `main` reporting a green check.
//!
//! WHAT IT COMPARES. `fuzz/rust-toolchain.toml` names a dated nightly, and rustc's version
//! string carries the commit date rather than the channel date — `nightly-2026-05-03`
//! reports `1.97.0-nightly (20de910db 2026-05-02)` — so the two dates do not match by
//! construction and this script does not compare them. It compares the release channel:
//! when the file names a nightly, the compiler must be a nightly. A different nightly
//! fails later, loudly, at openmls 0.8.1's prelude (E0365), which is the condition
//! `fuzz/rust-toolchain.toml` records.

use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => dir,
        Err(err) => panic!(
            "cargo set no CARGO_MANIFEST_DIR, so this script cannot find rust-toolchain.toml: {err}"
        ),
    };
    let pin_path = Path::new(&manifest_dir).join("rust-toolchain.toml");
    println!("cargo:rerun-if-changed={}", pin_path.display());
    println!("cargo:rerun-if-env-changed=RUSTUP_TOOLCHAIN");

    let pin_text = match std::fs::read_to_string(&pin_path) {
        Ok(text) => text,
        Err(err) => panic!("cannot read {}: {err}", pin_path.display()),
    };
    let Some(channel) = pinned_channel(&pin_text) else {
        panic!("{} names no [toolchain] channel", pin_path.display());
    };

    // `RUSTC` is the compiler cargo is about to use for this crate, so asking it its
    // version reports what the build resolved rather than what any other rustc on PATH is.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = match Command::new(&rustc).arg("--version").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Ok(output) => panic!(
            "`{rustc} --version` exited {}, so the resolved compiler is unknown",
            output.status
        ),
        Err(err) => panic!("cannot run `{rustc} --version`: {err}"),
    };

    if channel.starts_with("nightly") && !version.contains("-nightly") {
        let override_var =
            std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "<unset>".to_string());
        panic!(
            "this build resolved `{version}`; {} names `{channel}`, and cargo-fuzz runs only on nightly.\n\
             RUSTUP_TOOLCHAIN={override_var} overrides a toolchain file when it is set; unset it and run the command again from inside `fuzz/`.\n\
             mise exports that variable when `.mise.toml` names a Rust version source, which is why `.mise.toml` names none.",
            pin_path.display(),
        );
    }
}

/// Returns the `channel` value of the `[toolchain]` table, reading the same shape
/// `scripts/hooks/pre-commit` and the ASSERT-PINNED-RUSTC block in `Dockerfile` read.
fn pinned_channel(toml_text: &str) -> Option<String> {
    for line in toml_text.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("channel") else {
            continue;
        };
        let Some(value) = value.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim();
        let Some(value) = value.strip_prefix('"') else {
            continue;
        };
        let Some(end) = value.find('"') else {
            continue;
        };
        return Some(value[..end].to_string());
    }
    None
}
