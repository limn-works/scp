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
#include <stddef.h>
typedef int32_t napi_status;
typedef void* napi_env;
typedef void* napi_ref;
typedef void* napi_value;
typedef void* napi_threadsafe_function;
typedef int napi_threadsafe_function_call_mode;
napi_status napi_delete_reference(napi_env env, napi_ref ref) {
    (void)env; (void)ref;
    return 0;
}
napi_status napi_reference_unref(napi_env env, napi_ref ref, uint32_t* result) {
    (void)env; (void)ref;
    if (result) *result = 0;
    return 0;
}
napi_status napi_call_threadsafe_function(napi_threadsafe_function func,
                                          void* data,
                                          napi_threadsafe_function_call_mode mode) {
    (void)func; (void)data; (void)mode;
    return 0;
}
napi_status napi_create_error(napi_env env, napi_value code, napi_value msg, napi_value* result) {
    (void)env; (void)code; (void)msg;
    if (result) *result = 0;
    return 0;
}
napi_status napi_create_string_utf8(napi_env env, const char* str, size_t len, napi_value* result) {
    (void)env; (void)str; (void)len;
    if (result) *result = 0;
    return 0;
}
napi_status napi_get_and_clear_last_exception(napi_env env, napi_value* result) {
    (void)env;
    if (result) *result = 0;
    return 0;
}
napi_status napi_get_reference_value(napi_env env, napi_ref ref, napi_value* result) {
    (void)env; (void)ref;
    if (result) *result = 0;
    return 0;
}
napi_status napi_is_error(napi_env env, napi_value value, _Bool* result) {
    (void)env; (void)value;
    if (result) *result = 0;
    return 0;
}
napi_status napi_is_exception_pending(napi_env env, _Bool* result) {
    (void)env;
    if (result) *result = 0;
    return 0;
}
napi_status napi_set_named_property(napi_env env, napi_value object, const char* utf8name, napi_value value) {
    (void)env; (void)object; (void)utf8name; (void)value;
    return 0;
}
napi_status napi_throw(napi_env env, napi_value error) {
    (void)env; (void)error;
    return 0;
}
",
    )
    .is_ok()
    {
        cc::Build::new().file(&stub_path).compile("napi_test_stubs");
    }
}
