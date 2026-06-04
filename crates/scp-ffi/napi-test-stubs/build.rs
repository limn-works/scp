const NAPI_TEST_STUBS: &str = r"
#include <stdint.h>
#include <stddef.h>

typedef int32_t napi_status;
typedef void* napi_env;
typedef void* napi_ref;
typedef void* napi_value;
typedef void* napi_threadsafe_function;
typedef int32_t napi_threadsafe_function_call_mode;

napi_status napi_delete_reference(napi_env env, napi_ref ref) { (void)env; (void)ref; return 0; }
napi_status napi_reference_unref(napi_env env, napi_ref ref, uint32_t* r) { (void)env; (void)ref; if (r) *r = 0; return 0; }
napi_status napi_reference_ref(napi_env env, napi_ref ref, uint32_t* r) { (void)env; (void)ref; if (r) *r = 0; return 0; }
napi_status napi_get_reference_value(napi_env env, napi_ref ref, napi_value* r) { (void)env; (void)ref; if (r) *r = (napi_value)0; return 0; }
napi_status napi_create_reference(napi_env env, napi_value v, uint32_t rc, napi_ref* r) { (void)env; (void)v; (void)rc; if (r) *r = (napi_ref)0; return 0; }
napi_status napi_is_error(napi_env env, napi_value v, int* r) { (void)env; (void)v; if (r) *r = 0; return 0; }
napi_status napi_create_error(napi_env env, napi_value c, napi_value m, napi_value* r) { (void)env; (void)c; (void)m; if (r) *r = (napi_value)0; return 0; }
napi_status napi_throw(napi_env env, napi_value e) { (void)env; (void)e; return 0; }
napi_status napi_is_exception_pending(napi_env env, int* r) { (void)env; if (r) *r = 0; return 0; }
napi_status napi_get_and_clear_last_exception(napi_env env, napi_value* r) { (void)env; if (r) *r = (napi_value)0; return 0; }
napi_status napi_create_string_utf8(napi_env env, const char* s, size_t l, napi_value* r) { (void)env; (void)s; (void)l; if (r) *r = (napi_value)0; return 0; }
napi_status napi_set_named_property(napi_env env, napi_value o, const char* n, napi_value v) { (void)env; (void)o; (void)n; (void)v; return 0; }
napi_status napi_call_threadsafe_function(napi_threadsafe_function f, void* d, napi_threadsafe_function_call_mode b) { (void)f; (void)d; (void)b; return 0; }
napi_status napi_release_threadsafe_function(napi_threadsafe_function f, int32_t mode) { (void)f; (void)mode; return 0; }
napi_status napi_acquire_threadsafe_function(napi_threadsafe_function f) { (void)f; return 0; }
napi_status napi_ref_threadsafe_function(napi_env env, napi_threadsafe_function f) { (void)env; (void)f; return 0; }
napi_status napi_unref_threadsafe_function(napi_env env, napi_threadsafe_function f) { (void)env; (void)f; return 0; }
napi_status napi_create_threadsafe_function(napi_env env, napi_value func, napi_value res, napi_value name, size_t max_queue, size_t initial_thread, void* ctx, void* finalize_cb, void* finalize_data, void* call_js_cb, napi_threadsafe_function* r) { (void)env; (void)func; (void)res; (void)name; (void)max_queue; (void)initial_thread; (void)ctx; (void)finalize_cb; (void)finalize_data; (void)call_js_cb; if (r) *r = (napi_threadsafe_function)0; return 0; }
";

fn main() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let stub_path = format!("{out_dir}/napi_test_stubs.c");
    if std::fs::write(&stub_path, NAPI_TEST_STUBS).is_err() {
        return;
    }
    cc::Build::new().file(&stub_path).compile("napi_test_stubs");
}
