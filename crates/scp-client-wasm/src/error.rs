//! Error mapping for the browser participant surface.
//!
//! Restores the deleted WASM bridge's error *shape* (`crates/scp-ffi/wasm/`,
//! pinned at `1a3b41a5e^`): every failure crosses the JS boundary as a thrown
//! exception carrying a stable, machine-readable `[SCP-{CATEGORY}-{NUMBER}]`
//! code prefix plus a human-readable message, so the TypeScript SDK can map it
//! to the cross-SDK `ScpError` hierarchy (`.docs/standards/sdk-common.md`).
//!
//! It does **not** restore the deleted module's body: that one mapped
//! `scp_ffi_common` errors and pulled the tokio-coupled FFI-common crate. This
//! one maps [`scp_client::ClientError`] — the single error the participant
//! driver surfaces — so it stays inside the ADR-057 wasm fence (no
//! `scp-runtime` / `scp-identity` / `scp_ffi_common`).
//!
//! # Redaction
//!
//! The driver runs the §9.16 double-encryption / MLS crypto path. The wrapped
//! lower-layer errors ([`scp_mls::MlsError`] and friends) are written to never
//! interpolate key material or plaintext into their `Display` (the driver's
//! `Codec` messages name only the failing wire object). This module therefore
//! forwards their message verbatim; it adds the code prefix and nothing else.

use scp_client::ClientError;
use wasm_bindgen::JsValue;

/// Stable error-code prefix for each [`ClientError`] category.
///
/// The numbers slot into the cross-SDK ranges documented in
/// `.docs/standards/sdk-common.md` (CTX 2000-2999, CRYPTO 4000-4999,
/// VALID 7000-7999, STORAGE 8000-8999). They are part of the public JS error
/// contract — append new variants, never renumber existing ones.
///
/// This is a pure `&ClientError -> &str` mapping with no `JsValue` dependency,
/// so it is testable on the native host (where `JsValue` construction aborts —
/// wasm-bindgen imported calls cannot run off-wasm). The `JsValue` wrapping in
/// [`to_js`] is covered by the wasm-target tests.
#[must_use]
pub const fn error_code(err: &ClientError) -> &'static str {
    match err {
        // MLS / sender-key / event-log are the cryptographic protocol layers.
        ClientError::Mls(_) => "SCP-CRYPTO-4010",
        ClientError::SenderKey(_) => "SCP-CRYPTO-4020",
        ClientError::EventLog(_) => "SCP-CRYPTO-4030",
        // Wire (de)serialization of MLS objects is a validation failure on
        // attacker-suppliable bytes.
        ClientError::Codec(_) => "SCP-VALID-7010",
        // Context lifecycle / membership.
        ClientError::UnknownContext(_) => "SCP-CTX-2001",
        ClientError::ContextAlreadyExists(_) => "SCP-CTX-2002",
        ClientError::UnsupportedMembershipChange(_) => "SCP-CTX-2003",
        // A driver invariant violation (bad argument / missing pending state).
        ClientError::Driver(_) => "SCP-CTX-2004",
        // The injected Storage backend failed at the I/O level (a
        // get/put/delete/list_keys fault) — distinct from a corrupt-but-readable
        // blob.
        ClientError::StorageBackend(_) => "SCP-STORAGE-8001",
        // A persisted snapshot could not be trusted for restore: it failed to
        // (de)serialize, carried an unknown format version, embedded a different
        // context id than its key, or failed the §9.9.3 checkpoint compare.
        ClientError::StorageCorrupt(_) => "SCP-STORAGE-8002",
        // A persisted snapshot belongs to a different identity than the restoring
        // client (its bound owner DID does not match).
        ClientError::StorageIdentityMismatch(_) => "SCP-STORAGE-8003",
    }
}

/// Converts a [`ClientError`] into a JS exception value carrying the stable
/// code prefix.
///
/// The resulting [`JsValue`] is a string of the form
/// `"[SCP-CRYPTO-4010] MLS error: …"`. wasm-bindgen turns a returned
/// `Err(JsValue)` into a thrown JS exception, so the TypeScript wrapper receives
/// it as `error.message` and parses the bracketed prefix.
#[must_use]
pub fn to_js(err: &ClientError) -> JsValue {
    JsValue::from_str(&format!("[{}] {err}", error_code(err)))
}

/// Maps a `Result<T, ClientError>` to `Result<T, JsValue>` for a
/// `#[wasm_bindgen]` method return.
///
/// # Errors
///
/// Propagates the input error as a code-prefixed [`JsValue`] (see [`to_js`]).
pub fn map_err<T>(result: Result<T, ClientError>) -> Result<T, JsValue> {
    result.map_err(|e| to_js(&e))
}

// Native-host tests: the pure `error_code` mapping. `JsValue` construction
// aborts off-wasm (wasm-bindgen imported calls cannot run natively), so the
// `to_js` / `map_err` `JsValue` behavior is covered by the wasm-target tests
// below instead.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_context_maps_to_stable_ctx_code() {
        let err = ClientError::UnknownContext("ctx-x".to_owned());
        assert_eq!(error_code(&err), "SCP-CTX-2001");
    }

    #[test]
    fn distinct_categories_get_distinct_codes() {
        let already = ClientError::ContextAlreadyExists("c".to_owned());
        let unsupported = ClientError::UnsupportedMembershipChange("c".to_owned());
        assert_ne!(error_code(&already), error_code(&unsupported));
    }

    #[test]
    fn storage_variants_map_to_distinct_stable_storage_codes() {
        // The three storage failure classes each get a distinct, stable code in
        // the SCP-STORAGE-8000 range (part of the public JS error contract).
        assert_eq!(
            error_code(&ClientError::StorageBackend("io".to_owned())),
            "SCP-STORAGE-8001"
        );
        assert_eq!(
            error_code(&ClientError::StorageCorrupt("checkpoint".to_owned())),
            "SCP-STORAGE-8002"
        );
        assert_eq!(
            error_code(&ClientError::StorageIdentityMismatch("owner".to_owned())),
            "SCP-STORAGE-8003"
        );
    }

    #[test]
    fn every_code_is_in_the_documented_prefix_space() {
        // A representative of each category resolves to a `SCP-` code.
        for err in [
            ClientError::UnknownContext("c".to_owned()),
            ClientError::ContextAlreadyExists("c".to_owned()),
            ClientError::UnsupportedMembershipChange("c".to_owned()),
            ClientError::Codec("c".to_owned()),
            ClientError::Driver("d".to_owned()),
            ClientError::StorageBackend("s".to_owned()),
            ClientError::StorageCorrupt("s".to_owned()),
            ClientError::StorageIdentityMismatch("s".to_owned()),
        ] {
            assert!(
                error_code(&err).starts_with("SCP-"),
                "code for {err:?} is in the SCP- prefix space"
            );
        }
    }
}

// wasm-target tests: the `JsValue` wrapping that cannot run on the native host.
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn to_js_carries_prefix_and_message() {
        let err = ClientError::UnknownContext("ctx-x".to_owned());
        let js = to_js(&err);
        let msg = js.as_string().unwrap_or_default();
        assert!(msg.starts_with("[SCP-CTX-2001] "), "prefix present: {msg}");
        assert!(msg.contains("ctx-x"), "message preserved: {msg}");
    }

    #[wasm_bindgen_test]
    fn map_err_threads_ok_through() {
        let ok: Result<u8, ClientError> = Ok(7);
        assert_eq!(map_err(ok).unwrap_or(0), 7);
    }
}
