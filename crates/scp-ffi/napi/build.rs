fn main() {
    napi_build::setup();

    // When building a test binary (not the cdylib), the napi C symbols are
    // unavailable because there is no Node.js runtime to link against.
    // Provide weak stub symbols so the test binary can link. For the cdylib
    // build, the real symbols from the Node.js binary take precedence.
    //
    // This is needed because scp-transport (and other large deps) prevent
    // the linker from dead-stripping napi::Error::Drop which references
    // napi_delete_reference and napi_reference_unref.
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let stub_path = format!("{out_dir}/napi_test_stubs.c");
    if std::fs::write(
        &stub_path,
        r"
// Stub napi symbols for test binary linkage.
// For cdylib builds, the real Node.js symbols take precedence.
#include <stdint.h>
typedef int32_t napi_status;
typedef void* napi_env;
typedef void* napi_ref;
napi_status napi_delete_reference(napi_env env, napi_ref ref) {
    (void)env; (void)ref;
    return 0;
}
napi_status napi_reference_unref(napi_env env, napi_ref ref, uint32_t* result) {
    (void)env; (void)ref;
    if (result) *result = 0;
    return 0;
}
",
    )
    .is_ok()
    {
        cc::Build::new().file(&stub_path).compile("napi_test_stubs");
    }
}
