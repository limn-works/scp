//! JS-injected storage, adapted to the driver's [`scp_client::Storage`] trait.
//!
//! Restores the deleted WASM bridge's `JsStorage` extern shape
//! (`crates/scp-ffi/wasm/`, pinned at `1a3b41a5e^`): a JS object the TypeScript
//! wrapper injects, backed by a browser key/value store (`IndexedDB`, or
//! wa-sqlite/OPFS). The deleted extern exposed `get`/`set`/`delete` plus
//! `listKeys`/`exists`; the driver's [`scp_client::Storage`] trait needs
//! `get`/`put`/`delete`/`list_keys` (out-of-band snapshot persistence + reopen
//! enumeration — ADR-057 component 3, T2), so the adapter binds exactly those
//! four and nothing speculative.
//!
//! # Synchronous-facade embedder contract (ADR-057 T2)
//!
//! [`scp_client::Storage`] is **synchronous** (the single-tab driver calls it
//! inline under `&mut self`), but a browser's durable store (`IndexedDB`) is
//! **asynchronous**. The injected `JsStorage` therefore MUST be a *synchronous
//! facade over an in-memory mirror*: on tab open the TypeScript SDK preloads the
//! client's keyspace (the `scp-client/*` prefix) into an in-memory `Map`, serves
//! `get`/`listKeys`/`set`/`delete` synchronously against that mirror, and
//! *write-behind*s each mutation to `IndexedDB` asynchronously. A durable-write
//! failure surfaces on a later call as a thrown exception (mapped to
//! `SCP-STORAGE-8010` here). Implementing that mirror is the TypeScript SDK's job
//! (ADR-057 Slice 3); this crate only defines the synchronous extern contract it
//! must satisfy.
//!
//! ## The write-behind flush is a crash-safety obligation: FIFO **and** fail-closed
//!
//! On a crash the durable store MUST be a strict **prefix** of the mutation
//! sequence the driver issued — never a **reorder** and never a **gap**. The
//! driver's crash-consistency invariants silently depend on it, because they
//! reason about *ordering* between two writes to different keys:
//!
//! - **Join** persists the joined-context snapshot (`put ctx/{id}`) and only THEN
//!   deletes the consumed pending blob (`delete pending/{id}`). If the durable
//!   store landed the delete but lost the put, neither a context nor its pending
//!   material would survive — a join that can be neither used nor resumed.
//! - **Close** deletes the durable snapshot (`delete ctx/{id}`) *before* dropping
//!   in-memory state, so a "closed" context is never durably resurrected. If a
//!   later unrelated write landed ahead of this delete, the snapshot would survive
//!   — resurrecting the closed context.
//!
//! The prefix requires the embedder to honor **two** obligations; neither alone is
//! sufficient:
//!
//! 1. **FIFO ordering.** Flush mutations in the order the driver issued them. This
//!    gives *no reorder*.
//! 2. **Fail-closed-sticky on any durable-write fault.** On the FIRST durable-write
//!    failure the embedder MUST (a) stop flushing every *subsequently-issued*
//!    mutation — never let a later op land after an earlier op faulted — and (b)
//!    fail every subsequent synchronous call closed (`SCP-STORAGE-8010`), stickily,
//!    until the store is **re-opened** (a re-open re-preloads the durable prefix
//!    into a fresh, un-faulted mirror). This gives *no gap*.
//!
//! FIFO alone does NOT deliver the prefix: a NON-UNIFORM durable-write fault (no
//! reorder at all) still breaks it. Concretely, Join's `put ctx/{id}` faults (quota
//! exceeded) while the subsequent `delete pending/{id}` *succeeds* (it frees space)
//! — the durable store now holds the delete without the put: a **gap**, the exact
//! consumed-KeyPackage-with-no-recoverable-context crash the ordering exists to
//! prevent. Halting the chain on the first fault keeps the store a strict prefix
//! (up to the first failed op); resuming after a fault produces the gap. So: FIFO
//! gives ORDERING, sticky-fail-closed gives the PREFIX — the embedder needs BOTH.
//!
//! Losing the un-flushed **tail** from the first failed op onward is safe — that is
//! exactly the ADR-057 "lose the last unpersisted mutations" property. Both
//! obligations are the embedder's job, not something this crate can enforce; the
//! TypeScript `IndexedDbStorage` adapter implements them (a sticky `#pendingFault`
//! plus a `#chainPoisoned` gate that skips every op issued after a fault — see
//! `bindings/typescript-wasm/src/adapters/indexeddb-storage.ts`).
//!
//! Unlike the deleted bridge, the body is **not** a re-implementation of
//! storage logic — it forwards to the injected JS object and translates the
//! result into the driver's trait contract.
//!
//! # Single-thread soundness (the `Send + Sync` adaptation)
//!
//! [`scp_client::Storage`] requires `Send + Sync` (the driver holds it behind an
//! `Arc`). A wasm-bindgen JS handle (`JsStorage`) is `!Send + !Sync`: a
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
        /// `None`) if the key is genuinely absent. Throws on storage access
        /// failure — a thrown exception is a backend fault, NOT "absent", and is
        /// surfaced as `SCP-STORAGE-8010` rather than mistaken for a missing key
        /// (which would silently drop durable state).
        #[wasm_bindgen(method, catch, js_name = "get")]
        fn get(this: &JsStorage, key: &str) -> Result<Option<Vec<u8>>, JsValue>;

        /// Stores `value` under `key`, replacing any existing value. Throws on
        /// storage access failure or quota exhaustion.
        ///
        /// `value` is passed **by value** (an owned `Vec<u8>`), so wasm-bindgen
        /// marshals it as a JS-owned `Uint8Array` copy detached from wasm linear
        /// memory — NOT a `subarray` view into it (which `&[u8]` would produce).
        /// This is load-bearing: the embedder's natural `set(k, v) { map.set(k, v) }`
        /// retains the array, and a view would then alias wasm memory that later
        /// allocations reuse, silently corrupting every previously-stored snapshot.
        /// Handing over an owned copy makes the contract sound for any embedder,
        /// not only one that defensively copies.
        #[wasm_bindgen(method, catch, js_name = "set")]
        fn set(this: &JsStorage, key: &str, value: Vec<u8>) -> Result<(), JsValue>;

        /// Removes the value stored under `key`. Idempotent. Throws on storage
        /// access failure.
        #[wasm_bindgen(method, catch, js_name = "delete")]
        fn delete(this: &JsStorage, key: &str) -> Result<(), JsValue>;

        /// Returns every key in the mirror that starts with `prefix`, in
        /// unspecified order. The driver uses this to enumerate its persisted
        /// contexts and pending joins on reopen (there is no separate manifest).
        /// A browser backend serves this from the preloaded in-memory mirror (see
        /// the module "synchronous-facade" note). Throws on enumeration failure.
        #[wasm_bindgen(method, catch, js_name = "listKeys")]
        fn list_keys(this: &JsStorage, prefix: &str) -> Result<Vec<String>, JsValue>;
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
    /// string for the driver's fallible `Storage` contract.
    fn js_err(context: &str, e: &JsValue) -> String {
        let detail = e
            .as_string()
            .unwrap_or_else(|| "non-string JS exception".to_owned());
        format!("JsStorage.{context} failed: {detail}")
    }

    impl Storage for JsStorageAdapter {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
            // Propagate a thrown JS exception as `Err` — a backend read fault is
            // NOT the same as an absent key (`Ok(None)`). Swallowing it as absence
            // would let the driver silently drop durable state; the driver relies
            // on this distinction to fail restore closed (ADR-057 T2).
            self.inner.get(key).map_err(|e| js_err("get", &e))
        }

        fn put(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
            // Move the owned bytes into JS: wasm-bindgen hands the JS `set` a
            // detached `Uint8Array` copy (not a wasm-memory view), so an embedder
            // that retains the array cannot alias reused wasm memory.
            self.inner.set(key, value).map_err(|e| js_err("set", &e))
        }

        fn delete(&self, key: &str) -> Result<(), String> {
            self.inner.delete(key).map_err(|e| js_err("delete", &e))
        }

        fn list_keys(&self, prefix: &str) -> Result<Vec<String>, String> {
            self.inner
                .list_keys(prefix)
                .map_err(|e| js_err("listKeys", &e))
        }
    }
}
