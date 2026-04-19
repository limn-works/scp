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
//
// Patterns covered (each corresponds to one entry in
// REQUIRED_FIXTURE_PATTERNS in the scanner):
//   1.  plain `tokio::task::block_in_place`
//   2.  aliased import `use ... block_in_place as bip; bip(...)`
//   3.  stored Handle `.block_on(...)`
//   4.  multi-line `.block_on(...)` chain
//   5.  `Handle::current().block_on(...)`
//   6.  inside a closure
//   7.  inside a nested fn
//   8.  `Runtime::new()` construction
//   9.  fn-pointer rebind: `let f = tokio::task::block_in_place; f(|| ...)`
//   10. Runtime type alias: `type R = Runtime; R::new().block_on(...)`
//   11. `macro_rules!` definition that wraps a sync bridge primitive
//   12. invocation of a sync-bridge macro
//   13. `#[cfg(not(test))] mod prod_only { ... }` — production-only modules
//       MUST NOT be treated as test code and excluded.
//
// Plus two allow-listed sites (14, 15) that demonstrate the inline
// `// ci-allow: block-on: <reason>` directive is honored.
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

// Pattern 9: fn-pointer rebind. `let f = block_in_place; f(|| {})` is
// grammatically a plain identifier at the call site; the scanner must
// track let-binding aliases to flag it.
fn fn_pointer_rebind_block_in_place() {
    let fn_ptr = tokio::task::block_in_place;
    fn_ptr(|| {
        let _ = 9;
    });
}

// Pattern 10: Runtime type alias. `type R = Runtime; R::new()` evades a
// naive `path.endswith("Runtime")` check on the base path. The scanner
// must track type aliases and match R::new() as runtime_new.
fn runtime_type_alias_block_on() {
    type R = Runtime;
    let rt = R::new().unwrap();
    // `.block_on` is ALSO caught; this is the companion check.
    let _ = rt.block_on(async { 10 });
}

// Pattern 11: macro_rules! definition wrapping a sync bridge primitive.
// A macro that takes `$e:expr` and expands to `block_in_place(|| $e)`
// smuggles the primitive through the caller's token stream. The scanner
// must flag the definition itself so reviewers see the wrapper.
//
// Name starts with `__` to avoid lint/dead-code noise and to make the
// scanner's self-test anchor trivial (see pattern descriptor below).
#[allow(dead_code)]
fn __macro_rules_defined_at_module_scope() {
    // Inner definition so the fixture can anchor the hit by fn name.
    // `macro_rules!` inside a fn is valid Rust.
    macro_rules! sync_bridge {
        ($e:expr) => {
            tokio::task::block_in_place(|| $e)
        };
    }
    // Reference the macro to avoid "unused_macros".
    sync_bridge!({
        let _ = 11;
    });
}

// Pattern 12: invocation of a macro whose TOKEN STREAM at the call site
// carries `block_in_place` through as a token. This is the pass-through
// wrapping case — a scanner that only looks at call_expression misses
// this entirely because macro_invocation is a different AST node.
//
// NOTE: this is distinct from pattern 11. In pattern 11 the DEFINITION's
// body wraps the primitive and is caught at the definition site. In
// pattern 12 the invocation SITE contains the primitive as a token
// passed into the macro — e.g. an identity macro or an effect-wrapper
// macro.
#[allow(dead_code)]
fn macro_invocation_site() {
    // A pass-through macro. The macro body itself does NOT reference
    // `block_in_place`; the invocation does.
    macro_rules! identity {
        ($e:expr) => {
            $e
        };
    }
    // The invocation's token stream contains `block_in_place` — the
    // scanner must flag the invocation even though the macro's body
    // is clean.
    let _ = identity!(tokio::task::block_in_place(|| 12));
}

// Pattern 13: production-only module. `#[cfg(not(test))]` gates this
// module ONLY to production builds — it is NOT test code. A scanner
// that treats any cfg-with-"test" as test-gated would erroneously skip
// the call inside. The scanner must match only cfg gates that
// positively assert `test` being present (cfg(test), cfg(all(test,...)),
// cfg(any(test,...)) — NOT cfg(not(test)) and NOT cfg(feature="test")).
#[cfg(not(test))]
mod production_only_cfg_not_test {
    use tokio::runtime::Handle;
    #[allow(dead_code)]
    pub(super) fn inner() {
        let h = Handle::current();
        let _ = h.block_on(async { 13 });
    }
}

// Allow-listed site 1: block_on with directive on same line (with reason).
fn allowlisted_block_on(handle: &Handle) -> u32 {
    handle.block_on(async { 14 }) // ci-allow: block-on: fixture coverage for allow-list
}

// Allow-listed site 2: block_in_place with directive on same line.
fn allowlisted_block_in_place() {
    tokio::task::block_in_place(|| 15); // ci-allow: block-on: fixture coverage for allow-list
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
    fn_pointer_rebind_block_in_place();
    runtime_type_alias_block_on();
    __macro_rules_defined_at_module_scope();
    macro_invocation_site();
    allowlisted_block_in_place();
}
