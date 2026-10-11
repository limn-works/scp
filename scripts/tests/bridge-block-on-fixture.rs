// Fixture for `scripts/check-bridge-block-on.py --self-test`. Never compiled.
//
// Function names carry the expected verdict: `flag_*` holds a bare
// `.block_on` the gate must flag, `allow_*` a site whose directive has a
// reason, `test_*` test code the gate must not see, and `bad_directive_*` a
// directive with no reason, which is an error.

fn flag_bare_block_on(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

fn flag_multiline_block_on(rt: &tokio::runtime::Runtime) {
    let _ = rt
        .block_on(async { 1 });
}

fn flag_handle_block_on() {
    tokio::runtime::Handle::current().block_on(async {});
}

fn flag_block_on_in_macro(rt: &tokio::runtime::Runtime) {
    drop(vec![rt.block_on(async { 2 })]);
}

fn flag_block_on_in_closure(rt: &tokio::runtime::Runtime) {
    let run = || rt.block_on(async {});
    run();
}

#[cfg(feature = "testing")]
fn flag_testing_feature_is_not_test_code(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

#[cfg(not(test))]
fn flag_cfg_not_test_is_production(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}

fn allow_trailing_directive(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {}); // ci-allow: bridge-block-on: waits on no context actor
}

fn allow_directive_above(rt: &tokio::runtime::Runtime) {
    // ci-allow: bridge-block-on: the caller released the GIL
    rt.block_on(async {});
}

fn bad_directive_without_reason(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {}); // ci-allow: bridge-block-on:
}

#[test]
fn test_plain_test_fn() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {});
}

#[tokio::test]
async fn test_tokio_test_fn() {
    let _ = tokio::runtime::Handle::current();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {});
}

#[cfg(test)]
mod helpers {
    fn test_in_cfg_test_module(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
}

mod tests {
    fn test_in_tests_module(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
}
