/// Emits the Python shared library directory so that `cargo test` works
/// without manually setting `DYLD_LIBRARY_PATH`.
///
/// PyO3 handles finding Python at compile time, but on macOS the dynamic
/// linker (`dyld`) needs the library path at *runtime* too. This build
/// script queries the Python interpreter for its `LIBDIR` and emits
/// `cargo:rustc-link-search=native=...` so the test binaries can find
/// `libpython3.XX.dylib` automatically.
fn main() {
    // Only needed on macOS — Linux uses rpath or ld.so.conf.
    if std::env::consts::OS != "macos" {
        return;
    }

    // Find the python3.12 interpreter (mise puts it on PATH).
    let output = std::process::Command::new("python3.12")
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))",
        ])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let libdir = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !libdir.is_empty() {
                println!("cargo:rustc-link-search=native={libdir}");
                // Note: DYLD_LIBRARY_PATH must still be set externally for
                // test binary execution. cargo:rustc-env only makes the
                // value available via env!() at compile time, not as a
                // process environment variable at runtime.
            }
        }
    }

    // If python3.12 isn't found, fall back silently — the developer
    // can still set DYLD_LIBRARY_PATH manually.
}
