// Minimal napi-rs build setup. Weak napi-C stubs required by the test
// binary (but that MUST NOT be linked into the cdylib) are provided by
// the `scp-ffi-napi-test-stubs` dev-dependency — see that crate's
// build.rs for the full stub set and rationale.
fn main() {
    napi_build::setup();
}
