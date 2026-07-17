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
use scp_mls::MlsError;
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
        // A convergent committer-timestamp AAD failure (ADR-057): an add-Commit
        // carried no authenticated timestamp or a malformed one. A distinct,
        // stable code so a caller can tell a convergence-authentication rejection
        // apart from a generic MLS failure. These arrive wrapped in
        // `ClientError::Mls`, so they MUST be matched BEFORE the catch-all
        // `ClientError::Mls(_)` arm below.
        ClientError::Mls(
            MlsError::ConvergentTimestampMissing | MlsError::ConvergentTimestampMalformed(_),
        ) => "SCP-CRYPTO-4040",
        // MLS / sender-key / event-log are the cryptographic protocol layers.
        ClientError::Mls(_) => "SCP-CRYPTO-4010",
        ClientError::SenderKey(_) => "SCP-CRYPTO-4020",
        ClientError::EventLog(_) => "SCP-CRYPTO-4030",
        // Wire (de)serialization of MLS objects is a validation failure on
        // attacker-suppliable bytes.
        ClientError::Codec(_) => "SCP-VALID-7010",
        // A decrypted frame's content type did not match the relay channel it
        // arrived on (§9.10.4 defense-in-depth: a mis-routed announcement/app
        // frame). Benign-dropped in `handle_relay_frame`, so it is not normally
        // surfaced across the JS boundary; the distinct VALID code exists so it
        // is legible if it ever is (e.g. a direct `receive_*` call).
        ClientError::ChannelContentMismatch => "SCP-VALID-7011",
        // Context lifecycle / membership.
        ClientError::UnknownContext(_) => "SCP-CTX-2001",
        ClientError::ContextAlreadyExists(_) => "SCP-CTX-2002",
        ClientError::UnsupportedMembershipChange(_) => "SCP-CTX-2003",
        // A driver invariant violation (bad argument / missing pending state).
        ClientError::Driver(_) => "SCP-CTX-2004",
        // An app-data send hit an empty peer-pseudonym registry in a multi-member
        // context — retryable once peers' announcements are pumped in (§9.10.4,
        // ADR-057 transport slice). CTX band; distinct from the generic driver code.
        ClientError::PseudonymRegistryEmpty { .. } => "SCP-CTX-2040",
        // The injected outbound Socket failed to enqueue a relay frame (the
        // WebSocket is closed / a JS exception was thrown). Transport band.
        ClientError::Transport(_) => "SCP-TRANS-5010",
        // A join was attempted with no retained pending key package (never
        // generated, or already consumed by a prior join attempt — single-use per
        // attempt). Distinct from the generic Driver code so a caller can tell an
        // absent-pending-material join apart from other invariant violations and
        // route it to the reconstruct-from-durable retry path.
        ClientError::NoPendingJoinMaterial { .. } => "SCP-CTX-2005",
        // The injected Storage backend failed at the I/O level (a
        // get/put/delete/list_keys fault) — distinct from a corrupt-but-readable
        // blob. NOTE: 8001-8003 are already allocated by scp-kt-android's
        // AndroidStorage (key-not-found / storage-op-failed / key-derivation-failed);
        // the browser participant driver's storage codes start at 8010 to avoid
        // that collision (see `.docs/standards/sdk-common.md`, SCP-STORAGE- band).
        ClientError::StorageBackend(_) => "SCP-STORAGE-8010",
        // A persisted snapshot could not be trusted for restore: it failed to
        // (de)serialize, carried an unknown format version, embedded a different
        // context id than its key, or failed the §9.9.3 checkpoint compare.
        ClientError::StorageCorrupt(_) => "SCP-STORAGE-8011",
        // A persisted snapshot belongs to a different identity than the restoring
        // client (its bound owner DID does not match).
        ClientError::StorageIdentityMismatch(_) => "SCP-STORAGE-8012",
        // A context diverged: a storage write failed after its in-memory state
        // advanced irreversibly. The caller must reconstruct from the last durable
        // snapshot.
        ClientError::ContextPoisoned { .. } => "SCP-STORAGE-8013",
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
    fn convergent_timestamp_family_maps_to_distinct_crypto_code() {
        // ADR-057: both convergent-timestamp AAD failures (which arrive wrapped in
        // ClientError::Mls) get the distinct SCP-CRYPTO-4040 code, so a caller can
        // tell a convergence-authentication rejection apart from a generic MLS
        // failure. The distinct arm must be matched BEFORE the catch-all
        // ClientError::Mls(_) → 4010.
        for err in [
            ClientError::Mls(MlsError::ConvergentTimestampMissing),
            ClientError::Mls(MlsError::ConvergentTimestampMalformed("bad len".to_owned())),
        ] {
            assert_eq!(error_code(&err), "SCP-CRYPTO-4040");
        }
        // A different MLS failure still falls through to the generic MLS code.
        assert_eq!(
            error_code(&ClientError::Mls(MlsError::GroupDestroyed)),
            "SCP-CRYPTO-4010"
        );
    }

    #[test]
    fn no_pending_join_material_gets_its_own_distinct_ctx_code() {
        // The single-use-per-attempt join failure has a DISTINCT code from the
        // generic Driver invariant violation, so a caller can route it to the
        // reconstruct-from-durable retry path rather than treating it as a generic
        // bad-argument fault.
        let no_pending = ClientError::NoPendingJoinMaterial {
            context_id: "ctx".to_owned(),
        };
        assert_eq!(error_code(&no_pending), "SCP-CTX-2005");
        assert_ne!(
            error_code(&no_pending),
            error_code(&ClientError::Driver("d".to_owned())),
            "absent-pending-material is distinct from a generic Driver violation"
        );
    }

    #[test]
    fn channel_content_mismatch_gets_its_own_distinct_valid_code() {
        // The §9.10.4 mis-routed-frame validation failure has a DISTINCT code
        // from the generic MLS-wire codec failure, both in the VALID band, so a
        // caller can tell a channel/content binding rejection apart from a raw
        // deserialization fault even though the driver benign-drops it internally.
        assert_eq!(
            error_code(&ClientError::ChannelContentMismatch),
            "SCP-VALID-7011"
        );
        assert_ne!(
            error_code(&ClientError::ChannelContentMismatch),
            error_code(&ClientError::Codec("wire".to_owned())),
        );
    }

    #[test]
    fn storage_variants_map_to_distinct_stable_storage_codes() {
        // The four browser storage failure classes each get a distinct, stable
        // code in the SCP-STORAGE-8010+ sub-range (part of the public JS error
        // contract). 8001-8003 are reserved for scp-kt-android; the browser codes
        // start at 8010 to avoid that collision.
        assert_eq!(
            error_code(&ClientError::StorageBackend("io".to_owned())),
            "SCP-STORAGE-8010"
        );
        assert_eq!(
            error_code(&ClientError::StorageCorrupt("checkpoint".to_owned())),
            "SCP-STORAGE-8011"
        );
        assert_eq!(
            error_code(&ClientError::StorageIdentityMismatch("owner".to_owned())),
            "SCP-STORAGE-8012"
        );
        assert_eq!(
            error_code(&ClientError::ContextPoisoned {
                context_id: "ctx".to_owned()
            }),
            "SCP-STORAGE-8013"
        );
    }

    #[test]
    fn browser_storage_codes_avoid_the_android_reserved_low_block() {
        // Regression guard for the collision this renumber fixed: scp-kt-android's
        // AndroidStorage owns the low `800x` block, so every browser storage code
        // must sit at 8010 or above. Checked numerically (no reserved-code string
        // literal, so the grep guarding this crate against the old codes stays 0).
        for err in [
            ClientError::StorageBackend("s".to_owned()),
            ClientError::StorageCorrupt("s".to_owned()),
            ClientError::StorageIdentityMismatch("s".to_owned()),
            ClientError::ContextPoisoned {
                context_id: "c".to_owned(),
            },
        ] {
            let code = error_code(&err);
            // A non-storage / malformed code parses to 0 and trips the same assert.
            let number: u32 = code
                .strip_prefix("SCP-STORAGE-")
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            assert!(
                number >= 8010,
                "browser storage code {code} is in the Android-reserved low block (or malformed)"
            );
        }
    }

    #[test]
    fn every_code_is_in_the_documented_prefix_space() {
        // A representative of each category resolves to a `SCP-` code.
        for err in [
            ClientError::UnknownContext("c".to_owned()),
            ClientError::ContextAlreadyExists("c".to_owned()),
            ClientError::UnsupportedMembershipChange("c".to_owned()),
            ClientError::Codec("c".to_owned()),
            ClientError::ChannelContentMismatch,
            ClientError::Driver("d".to_owned()),
            ClientError::NoPendingJoinMaterial {
                context_id: "c".to_owned(),
            },
            ClientError::StorageBackend("s".to_owned()),
            ClientError::StorageCorrupt("s".to_owned()),
            ClientError::StorageIdentityMismatch("s".to_owned()),
            ClientError::ContextPoisoned {
                context_id: "c".to_owned(),
            },
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
