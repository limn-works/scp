// When building a test binary (not the cdylib), the napi C symbols are
// unavailable because there is no Node.js runtime to link against.
// Provide weak stub symbols so the test binary can link. For the cdylib
// build, the real symbols from the Node.js binary take precedence.
//
// This is needed because scp-transport (and other large deps) prevent
// the linker from dead-stripping code paths in napi-rs that reference
// napi_* functions transitively (e.g. via `JsError::into_value`,
// `JsError::throw_into`, `Buffer::drop`, etc.). The set of symbols below
// was determined empirically by iteratively linking `cargo test
// --workspace --features ... --no-run` and adding stubs until it linked.
//
// Each stub returns 0 (napi_ok) and writes safe defaults to any out
// params. No runtime behavior depends on these — the tests in this
// workspace do not exercise napi-rs paths that transitively call
// back into node runtime APIs; they only need the binary to link.

// All stubs are marked `__attribute__((weak))` so they only take effect
// when no stronger symbol is present. When the cdylib is loaded into Node
// (`require("./index.node")`), Node's real `napi_*` functions satisfy the
// unresolved references first and the weak stubs are never used — so the
// cdylib behaves identically to a build without this shim. For test
// binaries (where there is no Node runtime), the weak stubs provide the
// unresolved symbols needed to link.
//
// The stub set was determined empirically by iteratively linking
// `cargo test --workspace --features ... --no-run` and adding stubs
// until it linked. Each stub returns 0 (napi_ok) and writes safe
// defaults to any out params.
const NAPI_TEST_STUBS: &str = r"
// Weak stub napi symbols for test binary linkage.
// When loaded into Node.js via `require()`, Node's real napi_* symbols
// take precedence over these weak stubs and this file is effectively
// inert in the cdylib.
#include <stdint.h>
#include <stddef.h>

#define NAPI_WEAK __attribute__((weak))

typedef int32_t napi_status;
typedef void* napi_env;
typedef void* napi_ref;
typedef void* napi_value;
typedef void* napi_threadsafe_function;
typedef int32_t napi_threadsafe_function_call_mode;

// --- Reference management ---
NAPI_WEAK napi_status napi_delete_reference(napi_env env, napi_ref ref) {
    (void)env; (void)ref;
    return 0;
}
NAPI_WEAK napi_status napi_reference_unref(napi_env env, napi_ref ref, uint32_t* result) {
    (void)env; (void)ref;
    if (result) *result = 0;
    return 0;
}
NAPI_WEAK napi_status napi_reference_ref(napi_env env, napi_ref ref, uint32_t* result) {
    (void)env; (void)ref;
    if (result) *result = 0;
    return 0;
}
NAPI_WEAK napi_status napi_get_reference_value(napi_env env, napi_ref ref, napi_value* result) {
    (void)env; (void)ref;
    if (result) *result = (napi_value)0;
    return 0;
}
NAPI_WEAK napi_status napi_create_reference(napi_env env, napi_value value, uint32_t initial_refcount, napi_ref* result) {
    (void)env; (void)value; (void)initial_refcount;
    if (result) *result = (napi_ref)0;
    return 0;
}

// --- Error handling ---
NAPI_WEAK napi_status napi_is_error(napi_env env, napi_value value, int* result) {
    (void)env; (void)value;
    if (result) *result = 0;
    return 0;
}
NAPI_WEAK napi_status napi_create_error(napi_env env, napi_value code, napi_value msg, napi_value* result) {
    (void)env; (void)code; (void)msg;
    if (result) *result = (napi_value)0;
    return 0;
}
NAPI_WEAK napi_status napi_throw(napi_env env, napi_value error) {
    (void)env; (void)error;
    return 0;
}
NAPI_WEAK napi_status napi_throw_error(napi_env env, const char* code, const char* msg) {
    (void)env; (void)code; (void)msg;
    return 0;
}
NAPI_WEAK napi_status napi_throw_type_error(napi_env env, const char* code, const char* msg) {
    (void)env; (void)code; (void)msg;
    return 0;
}
NAPI_WEAK napi_status napi_throw_range_error(napi_env env, const char* code, const char* msg) {
    (void)env; (void)code; (void)msg;
    return 0;
}
NAPI_WEAK napi_status napi_is_exception_pending(napi_env env, int* result) {
    (void)env;
    if (result) *result = 0;
    return 0;
}
NAPI_WEAK napi_status napi_get_and_clear_last_exception(napi_env env, napi_value* result) {
    (void)env;
    if (result) *result = (napi_value)0;
    return 0;
}
NAPI_WEAK napi_status napi_fatal_error(const char* location, size_t location_len, const char* message, size_t message_len) {
    (void)location; (void)location_len; (void)message; (void)message_len;
    return 0;
}
NAPI_WEAK napi_status napi_fatal_exception(napi_env env, napi_value err) {
    (void)env; (void)err;
    return 0;
}
NAPI_WEAK napi_status napi_get_last_error_info(napi_env env, const void** result) {
    (void)env;
    if (result) *result = (const void*)0;
    return 0;
}

// --- String creation ---
NAPI_WEAK napi_status napi_create_string_utf8(napi_env env, const char* str, size_t length, napi_value* result) {
    (void)env; (void)str; (void)length;
    if (result) *result = (napi_value)0;
    return 0;
}
NAPI_WEAK napi_status napi_create_string_utf16(napi_env env, const uint16_t* str, size_t length, napi_value* result) {
    (void)env; (void)str; (void)length;
    if (result) *result = (napi_value)0;
    return 0;
}
NAPI_WEAK napi_status napi_create_string_latin1(napi_env env, const char* str, size_t length, napi_value* result) {
    (void)env; (void)str; (void)length;
    if (result) *result = (napi_value)0;
    return 0;
}

// --- Property manipulation ---
NAPI_WEAK napi_status napi_set_named_property(napi_env env, napi_value object, const char* utf8name, napi_value value) {
    (void)env; (void)object; (void)utf8name; (void)value;
    return 0;
}
NAPI_WEAK napi_status napi_get_named_property(napi_env env, napi_value object, const char* utf8name, napi_value* result) {
    (void)env; (void)object; (void)utf8name;
    if (result) *result = (napi_value)0;
    return 0;
}
NAPI_WEAK napi_status napi_has_named_property(napi_env env, napi_value object, const char* utf8name, int* result) {
    (void)env; (void)object; (void)utf8name;
    if (result) *result = 0;
    return 0;
}
NAPI_WEAK napi_status napi_set_property(napi_env env, napi_value object, napi_value key, napi_value value) {
    (void)env; (void)object; (void)key; (void)value;
    return 0;
}
NAPI_WEAK napi_status napi_get_property(napi_env env, napi_value object, napi_value key, napi_value* result) {
    (void)env; (void)object; (void)key;
    if (result) *result = (napi_value)0;
    return 0;
}

// --- Threadsafe functions ---
NAPI_WEAK napi_status napi_call_threadsafe_function(napi_threadsafe_function func, void* data, napi_threadsafe_function_call_mode is_blocking) {
    (void)func; (void)data; (void)is_blocking;
    return 0;
}
NAPI_WEAK napi_status napi_acquire_threadsafe_function(napi_threadsafe_function func) {
    (void)func;
    return 0;
}
NAPI_WEAK napi_status napi_release_threadsafe_function(napi_threadsafe_function func, int mode) {
    (void)func; (void)mode;
    return 0;
}
NAPI_WEAK napi_status napi_ref_threadsafe_function(napi_env env, napi_threadsafe_function func) {
    (void)env; (void)func;
    return 0;
}
NAPI_WEAK napi_status napi_unref_threadsafe_function(napi_env env, napi_threadsafe_function func) {
    (void)env; (void)func;
    return 0;
}
";

fn main() {
    napi_build::setup();

    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let stub_path = format!("{out_dir}/napi_test_stubs.c");
    if std::fs::write(&stub_path, NAPI_TEST_STUBS).is_ok() {
        cc::Build::new().file(&stub_path).compile("napi_test_stubs");
    }
}
