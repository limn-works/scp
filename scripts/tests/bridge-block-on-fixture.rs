// Fixture for `scripts/check-bridge-block-on.py --self-test`. Never compiled.
//
// Function names carry the expected verdict: `flag_*` holds a blocking wait
// the gate must flag, and `test_*` test code the gate must not see. The gate
// is a whitelist, so a `ci-allow` directive exempts nothing.

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

fn flag_old_trailing_directive(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {}); // ci-allow: bridge-block-on: waits on no context actor
}

fn flag_old_directive_above(rt: &tokio::runtime::Runtime) {
    // ci-allow: bridge-block-on: the caller released the GIL
    rt.block_on(async {});
}

fn flag_block_in_place() {
    tokio::task::block_in_place(|| ());
}

fn flag_ufcs_handle_block_on(h: &tokio::runtime::Handle) {
    tokio::runtime::Handle::block_on(h, async {});
}

fn flag_futures_executor_block_on() {
    futures::executor::block_on(async {});
}

fn flag_renaming_use() {
    use tokio::task::block_in_place as bip;
    bip(|| ());
}

fn flag_method_value(rt: &tokio::runtime::Runtime) {
    let wait = tokio::runtime::Runtime::block_on::<std::future::Ready<()>>;
    wait(rt, std::future::ready(()));
}

fn flag_second_helper_outside_the_helper_file(rt: &tokio::runtime::Runtime) {
    fn bridge_block_on(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
    bridge_block_on(rt);
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

// A module's name does not make it test code: without `cfg(test)` it
// compiles into production.
mod tests {
    fn flag_in_tests_module_without_cfg_test(rt: &tokio::runtime::Runtime) {
        rt.block_on(async {});
    }
}
