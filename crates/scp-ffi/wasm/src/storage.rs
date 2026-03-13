//! JS-injected storage callback types.
//!
//! The WASM bridge cannot use native file system storage or `SQLite` directly.
//! Instead, the TypeScript wrapper injects a `JsStorage` object backed by
//! one of two browser storage backends (per §17.6):
//!
//! 1. **Primary:** wa-sqlite with `OPFSCoopSyncVFS` (Origin Private File
//!    System) — full `SQLite` semantics in the browser.
//! 2. **Fallback:** `IndexedDB` — used when OPFS is unavailable (older browsers,
//!    non-secure contexts).
//!
//! The extern "C" block declares the JS interface. The TypeScript SDK is
//! responsible for detecting OPFS availability and providing the correct
//! implementation at the call site.
//!
//! # Storage injection pattern
//!
//! ```ts
//! // TypeScript wrapper builds an OPFS-backed storage object:
//! const storage = await buildOpfsStorage();    // or buildIdbStorage()
//! await context_create(identityDid, paramsJson);
//! ```
//!
//! # Key conventions
//!
//! Keys follow the `ProtocolRepository` key conventions from `scp-core/store/`:
//! - `identity/{did}` — identity state
//! - `context/{context_id}` — context state
//! - `key/{key_id}` — key material envelopes
//! - `event_log/{context_id}/{seq}` — event log entries
//!
//! # wasm-bindgen `catch` convention
//!
//! Methods annotated with `#[wasm_bindgen(method, catch)]` must return
//! `Result<T, JsValue>`. Thrown JS exceptions are caught by wasm-bindgen
//! and converted to `Err(JsValue)`.
//!
//! See ADR-022 in `.docs/adrs/phase-4.md` and spec §17.6 for the full spec.

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// JsStorage — injected browser storage (OPFS/IndexedDB)
// ---------------------------------------------------------------------------

/// Opaque JS object implementing key-value storage for the WASM bridge.
///
/// Declared as an extern type so that any JS object with the matching
/// method signatures can be passed in. The TypeScript SDK provides either
/// a wa-sqlite/OPFS implementation or an `IndexedDB` fallback.
///
/// All methods use `catch` so that thrown JS exceptions are converted to
/// `Err(JsValue)` at the Rust boundary.
#[wasm_bindgen]
extern "C" {
    /// A JS object that implements key-value storage for the WASM bridge.
    ///
    /// Implemented in TypeScript using wa-sqlite (OPFS primary) or
    /// `IndexedDB` (fallback). Injected at context and identity creation time.
    pub type JsStorage;

    /// Returns the value stored under `key`, or `undefined` (mapped to
    /// `None`) if the key does not exist.
    ///
    /// Throws on storage access failure.
    #[wasm_bindgen(method, catch, js_name = "get")]
    pub fn get(this: &JsStorage, key: &str) -> Result<Option<Vec<u8>>, JsValue>;

    /// Stores `value` under `key`, replacing any existing value.
    ///
    /// Throws on storage access failure or quota exceeded.
    #[wasm_bindgen(method, catch, js_name = "set")]
    pub fn set(this: &JsStorage, key: &str, value: &[u8]) -> Result<(), JsValue>;

    /// Removes the value stored under `key`.
    ///
    /// Idempotent — removing a non-existent key is a no-op.
    /// Throws on storage access failure.
    #[wasm_bindgen(method, catch, js_name = "delete")]
    pub fn delete(this: &JsStorage, key: &str) -> Result<(), JsValue>;

    /// Returns all keys that start with `prefix`.
    ///
    /// Returns an empty array if no keys match.
    /// Throws on storage access failure.
    #[wasm_bindgen(method, catch, js_name = "listKeys")]
    pub fn list_keys(this: &JsStorage, prefix: &str) -> Result<Vec<String>, JsValue>;

    /// Returns `true` if a value is stored under `key`.
    ///
    /// Throws on storage access failure.
    #[wasm_bindgen(method, catch, js_name = "exists")]
    pub fn exists(this: &JsStorage, key: &str) -> Result<bool, JsValue>;
}
