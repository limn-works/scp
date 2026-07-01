//! JS-injected storage, adapted to the driver's [`scp_client::Storage`] trait.
//!
//! Restores the deleted WASM bridge's `JsStorage` extern shape
//! (`crates/scp-ffi/wasm/`, pinned at `1a3b41a5e^`): a JS object the TypeScript
//! wrapper injects, backed by a browser key/value store (`IndexedDB`, or
//! wa-sqlite/OPFS). The deleted extern exposed `get`/`set`/`delete` plus
//! `listKeys`/`exists`; the driver's [`scp_client::Storage`] trait needs only
//! `get`/`put`/`delete` (out-of-band snapshot persistence — ADR-057 component
//! 3), so the adapter binds exactly those three and nothing speculative.
//!
//! Unlike the deleted bridge, the body is **not** a re-implementation of
//! storage logic — it forwards to the injected JS object and translates the
//! result into the driver's trait contract.
//!
//! # Single-thread soundness (the `Send + Sync` adaptation)
//!
//! [`scp_client::Storage`] requires `Send + Sync` (the driver holds it behind an
//! `Arc`). A wasm-bindgen JS handle ([`JsStorage`]) is `!Send + !Sync`: a
//! `JsValue` is an index into the JS module's heap and is meaningless in any
//! other agent's heap. The browser participant model is **single-threaded by
//! construction** — one `ScpClient` per tab, driven by `&mut self` with no
//! internal concurrency (ADR-057's single-tab driver). The `unsafe impl Send +
//! Sync` below bridges the trait bound under exactly that model; it is the
//! standard wasm-bindgen single-thread idiom, scoped to this adapter and
//! compiled only under `wasm32`. It does **not** relax the shared
//! [`scp_client::Storage`] bound (which would ripple into the native runtime);
//! the `unsafe` is localized entirely to the browser surface.
//!
//! ## Embedder obligation (the real boundary of the invariant)
//!
//! `wasm32-unknown-unknown` is *usually* single-threaded, but the WebAssembly
//! threads proposal (shared memory + web-worker agents) can make it not so. The
//! `JsValue` itself **cannot** cross an agent boundary regardless — it would be
//! a dangling heap index — so the `unsafe` is sound *as long as a live
//! `WasmScpClient` (and the `JsStorage`/`JsKeyCustody` it holds) is never
//! transferred to another worker agent*. That is a real obligation on the
//! browser SDK embedder, not an absolute guarantee this crate can enforce. The
//! single-tab cold-presence model (ADR-057) holds it by construction; an
//! embedder that wires shared-memory threads MUST keep one client pinned to one
//! agent. This is the honest scope of the `unsafe`, stated so a future
//! multi-worker integration does not silently violate it.

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::{JsStorage, JsStorageAdapter};

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use scp_client::Storage;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        /// Opaque JS object implementing browser key/value storage.
        ///
        /// The TypeScript SDK injects a conforming implementation
        /// (`IndexedDB`, or wa-sqlite/OPFS). Each method uses `catch`, so a
        /// thrown JS exception surfaces as `Err(JsValue)` at this boundary.
        pub type JsStorage;

        /// Returns the value stored under `key`, or `undefined` (mapped to
        /// `None`) if absent. Throws on storage access failure.
        #[wasm_bindgen(method, catch, js_name = "get")]
        fn get(this: &JsStorage, key: &str) -> Result<Option<Vec<u8>>, JsValue>;

        /// Stores `value` under `key`, replacing any existing value. Throws on
        /// storage access failure or quota exhaustion.
        #[wasm_bindgen(method, catch, js_name = "set")]
        fn set(this: &JsStorage, key: &str, value: &[u8]) -> Result<(), JsValue>;

        /// Removes the value stored under `key`. Idempotent. Throws on storage
        /// access failure.
        #[wasm_bindgen(method, catch, js_name = "delete")]
        fn delete(this: &JsStorage, key: &str) -> Result<(), JsValue>;
    }

    /// Adapts an injected [`JsStorage`] to the driver's [`Storage`] trait.
    pub struct JsStorageAdapter {
        inner: JsStorage,
    }

    impl JsStorageAdapter {
        /// Wraps an injected JS storage object.
        #[must_use]
        pub fn new(inner: JsStorage) -> Self {
            Self { inner }
        }
    }

    // SAFETY: see the module-level "Single-thread soundness" + "Embedder
    // obligation" notes. The wrapped `JsStorage` handle is a JS-heap index that
    // cannot cross a worker-agent boundary; under the single-tab driver model it
    // is never sent to another agent, so the `Send + Sync` the driver requires
    // is satisfied. Compiled ONLY for wasm32. The embedder must keep one client
    // pinned to one agent if it ever wires shared-memory threads.
    unsafe impl Send for JsStorageAdapter {}
    // SAFETY: as above (see module docs).
    unsafe impl Sync for JsStorageAdapter {}

    /// Renders a `JsValue` thrown by the injected storage as a stable error
    /// string for the driver's `Result<(), String>` / `Option` contract.
    fn js_err(context: &str, e: &JsValue) -> String {
        let detail = e
            .as_string()
            .unwrap_or_else(|| "non-string JS exception".to_owned());
        format!("JsStorage.{context} failed: {detail}")
    }

    impl Storage for JsStorageAdapter {
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            // The trait's `get` is infallible-by-value (returns `Option`). A
            // storage backend that throws on read is a hard environment fault
            // the trait cannot surface; treat it as "absent" so callers fall
            // back to a fresh read/rebuild rather than wedging. A browser
            // backend should not throw on a plain key read in practice.
            self.inner.get(key).ok().flatten()
        }

        fn put(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
            self.inner.set(key, &value).map_err(|e| js_err("set", &e))
        }

        fn delete(&self, key: &str) -> Result<(), String> {
            self.inner.delete(key).map_err(|e| js_err("delete", &e))
        }
    }
}
