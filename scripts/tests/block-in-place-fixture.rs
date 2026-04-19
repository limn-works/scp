// ---------------------------------------------------------------------------
// Self-test fixture for scripts/check-block-in-place.py.
//
// This file is deliberately NOT compiled by cargo — it lives under
// `scripts/tests/` and is consumed only by the CI AST checker. Every known
// bypass pattern that a grep-based checker would miss appears here, plus
// the two legitimate allow-list annotations.
//
// DO NOT add `mod block_in_place_fixture;` anywhere. This is never built.
//
// Run:
//   python3.12 scripts/check-block-in-place.py --self-test
// The script asserts every pattern below is caught, and that the two
// allow-listed sites are tagged (not counted).
// ---------------------------------------------------------------------------

use tokio::runtime::{Handle, Runtime};
use tokio::task::block_in_place as bip; // aliased import

// Pattern 1: plain tokio::task::block_in_place
fn plain_block_in_place() {
    tokio::task::block_in_place(|| {
        let _ = 1 + 1;
    });
}

// Pattern 2: aliased import (`bip`) must still be caught by AST resolver
fn aliased_block_in_place() {
    bip(|| {
        let _ = 2 + 2;
    });
}

// Pattern 3: stored Handle, .block_on(...)
struct Holder {
    handle: Handle,
}

impl Holder {
    fn stored_handle_block_on(&self, x: u32) -> u32 {
        self.handle.block_on(async move { x * 2 })
    }
}

// Pattern 4: multi-line .block_on chain (grep regex on the same line fails)
fn multiline_block_on(handle: &Handle) {
    let _ = handle
        .block_on(async {
            let _ = 3;
            4
        });
}

// Pattern 5: Handle::current().block_on(...)
fn handle_current_block_on() {
    let _ = Handle::current().block_on(async { 5 });
}

// Pattern 6: inside a closure
fn closure_block_on() {
    let f = |h: &Handle| {
        // The call is inside a closure body; AST walker must recurse into it.
        h.block_on(async { 6 })
    };
    let _ = f;
}

// Pattern 7: inside a nested fn
fn with_nested_fn(handle: &Handle) -> u32 {
    fn nested_fn_block_on(h: &Handle) -> u32 {
        h.block_on(async { 7 })
    }
    nested_fn_block_on(handle)
}

// Pattern 8: Runtime::new() construction
fn runtime_new_then_block_on() {
    let rt = Runtime::new().unwrap();
    let _ = rt.block_on(async { 8 });
}

// Allow-listed site 1: block_on with directive on same line (with reason).
fn allowlisted_block_on(handle: &Handle) -> u32 {
    handle.block_on(async { 9 }) // ci-allow: block-on: fixture coverage for allow-list
}

// Allow-listed site 2: block_in_place with directive on same line.
fn allowlisted_block_in_place() {
    tokio::task::block_in_place(|| 10); // ci-allow: block-on: fixture coverage for allow-list
}

// ---------------------------------------------------------------------------
// NOTE: The following are intentionally NOT present in this fixture:
//
//   - An allow-list with empty reason (e.g. `// ci-allow: block-on`). This
//     would be a reject pattern; it lives in the scanner's error-path unit
//     test surface, not in this "must-catch" fixture.
//   - Test-module-scoped calls. Those are expected to be IGNORED by the
//     scanner (mod tests is excluded). Testing the inclusion path alone is
//     sufficient here.
// ---------------------------------------------------------------------------

// Reference items to silence "unused function" if this file were ever built.
// It is NOT built, but guarding against accidental inclusion is cheap.
#[allow(dead_code)]
pub(crate) fn __fixture_entrypoints() {
    plain_block_in_place();
    aliased_block_in_place();
    handle_current_block_on();
    closure_block_on();
    runtime_new_then_block_on();
    allowlisted_block_in_place();
}
