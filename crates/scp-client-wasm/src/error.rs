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

/// The code emitted for a browser-participant wire/input (de)serialization or
/// byte-shape validation failure.
///
/// Shared by [`ClientError::Codec`] (via [`error_code`]) AND the `lib.rs` wasm
/// free-function input validators (`request_id`/`operator_pk`/`caveats_binding`
/// length, `OutletStreamChunk` decode, event-log & wrapping-key `MessagePack`
/// serde), which construct their `JsValue` message DIRECTLY rather than through
/// [`error_code`]. Routing every emitter through this ONE constant makes a typo
/// impossible and lets the exhaustive allowlist test pin all of them at once
/// (`error_code(Codec)` returns this constant, and the test asserts its value).
///
/// Registered as `scp-client-wasm` in `.docs/standards/sdk-common.md`; verified
/// free across all five surfaces (native/swift/kotlin/ts-native/ts-wasm).
pub(crate) const WASM_INPUT_VALIDATION_CODE: &str = "SCP-VALID-7028";

/// Stable error-code prefix for each [`ClientError`] category.
///
/// The numbers are the reconciled per-code meanings registered in
/// `.docs/standards/sdk-common.md` ("Registered SCP-CTX- / SCP-CRYPTO- /
/// SCP-TRANS- / SCP-VALID- codes"). That ledger is the single source of truth
/// for the browser-owned allocations. The numbers were chosen by an exhaustive
/// manual cross-surface review (the process `scripts/check-error-codes.sh`
/// Phase-2 mandates for the SDK-wrapper surfaces it cannot machine-check): every
/// browser-owned code here is FREE across all five surfaces (native
/// FFI-common registry, Swift, Kotlin, ts-native, ts-wasm). The ONE exception is
/// the deliberate reuse of `SCP-CTX-2095` (pseudonym-registry-empty), whose
/// meaning is identical on native + Swift + Kotlin + ts-native + this surface.
/// (Native CTX-2003 is NOT reused: native means "already exists" but Swift means
/// "message stream already active" and Kotlin "not a member" — a pre-existing
/// cross-surface overload — so `ContextAlreadyExists` took a fresh browser-owned
/// number instead.) This crate cannot import the native registry (the ADR-057
/// wasm/tokio fence), so these literals are hand-written and kept in agreement
/// with the ledger by the exhaustive allowlist test below. The numbers are part
/// of the public JS error contract — never silently renumber; a change must move
/// the ledger row first (after re-running the cross-surface union check).
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
        // Generic MLS group operation catch-all (create/add/join/encrypt/decrypt/
        // commit). A browser-owned crypto code, distinct from the native registry's
        // CRYPTO-4010 ("MLS group create error"), whose narrower meaning this
        // catch-all does not share (see the registered-codes table in sdk-common.md).
        ClientError::Mls(_) => "SCP-CRYPTO-4041",
        // Sender-key (§9.16) and event-log are the other browser crypto layers.
        // The driver reaches no #active/#agent key, so it refuses to mint a
        // KeyPackage whose §9.7.1 attestation it cannot sign. Distinct from
        // SCP-CRYPTO-4041 so a caller can tell "this build cannot join a
        // context on its own" apart from a failed MLS operation.
        ClientError::AttestationSignerUnavailable => "SCP-CRYPTO-4042",
        ClientError::SenderKey(_) => "SCP-CRYPTO-4020",
        ClientError::EventLog(_) => "SCP-CRYPTO-4030",
        // Wire (de)serialization of MLS objects is a validation failure on
        // attacker-suppliable bytes. Browser-owned VALID code (7028), free across
        // all five surfaces. The wasm free-function input validators
        // (request_id/operator_pk/caveats length, OutletStreamChunk decode,
        // event-log & wrapping-key serde) emit this SAME code — one meaning:
        // "browser wire/input validation failure" — via the shared constant.
        ClientError::Codec(_) => WASM_INPUT_VALIDATION_CODE,
        // A decrypted frame's content type did not match the relay channel it
        // arrived on (§9.10.4 defense-in-depth: a mis-routed announcement/app
        // frame). Benign-dropped in `handle_relay_frame`, so it is not normally
        // surfaced across the JS boundary; the distinct browser-owned VALID code
        // (7029) exists so it is legible if it ever is (e.g. a direct `receive_*`
        // call). Free across all five surfaces.
        ClientError::ChannelContentMismatch => "SCP-VALID-7029",
        // Context lifecycle / membership. `UnknownContext`, `ContextAlreadyExists`,
        // `UnsupportedMembershipChange`, and `Driver` are browser-owned CTX codes
        // (2082-2085), each verified FREE across all five surfaces. In particular
        // `ContextAlreadyExists` does NOT reuse native CTX-2003 ("already exists"):
        // that number is already overloaded off-native (Swift = "message stream
        // already active", Kotlin = "not a member"), so a fresh code is minted.
        ClientError::UnknownContext(_) => "SCP-CTX-2082",
        ClientError::ContextAlreadyExists(_) => "SCP-CTX-2083",
        ClientError::UnsupportedMembershipChange(_) => "SCP-CTX-2084",
        // A driver invariant violation (bad argument / missing pending state).
        ClientError::Driver(_) => "SCP-CTX-2085",
        // An app-data send hit an empty peer-pseudonym registry in a multi-member
        // context — retryable once peers' announcements are pumped in (§9.10.4,
        // ADR-057 transport slice). Semantically IDENTICAL to native
        // `ContextError::PseudonymRegistryEmpty` (`SCP-CTX-2095`) — and the same
        // meaning on Swift, Kotlin, and ts-native — so it is the ONE deliberate
        // cross-surface shared-meaning reuse (sdk-common.md).
        ClientError::PseudonymRegistryEmpty { .. } => "SCP-CTX-2095",
        // The injected outbound Socket failed to enqueue a relay frame (the
        // WebSocket is closed / a JS exception was thrown). Browser-owned Transport
        // code (5005), free across all five surfaces.
        ClientError::Transport(_) => "SCP-TRANS-5005",
        // A join was attempted with no retained pending key package (never
        // generated, or already consumed by a prior join attempt — single-use per
        // attempt). Browser-owned CTX code (2086), distinct from the generic Driver
        // code so a caller can route it to the reconstruct-from-durable retry path.
        // (2080/2081 are taken by Kotlin, so this sits at 2086 — free across five.)
        ClientError::NoPendingJoinMaterial { .. } => "SCP-CTX-2086",
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
/// `"[SCP-CRYPTO-4041] MLS error: …"`. wasm-bindgen turns a returned
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

    /// The reconciled `error_code()` value expected for every [`ClientError`]
    /// variant, as an EXHAUSTIVE positive allowlist.
    ///
    /// This is deliberately an independent, no-wildcard `match` over the whole
    /// `ClientError` enum: it is the single-source-of-truth mirror of the
    /// `.docs/standards/sdk-common.md` ledger expressed as code. Its purpose is
    /// twofold and both halves are load-bearing:
    ///
    /// 1. **Exhaustiveness (a closed whitelist).** Because there is NO `_`
    ///    wildcard, adding a new `ClientError` variant fails to compile HERE
    ///    until an arm — and thus a deliberate ledger decision — is added. A new
    ///    variant cannot silently fall through to an unaudited code.
    /// 2. **Value pinning.** Every arm is a literal reconciled code. If
    ///    `error_code()` is edited to emit a different (e.g. native-colliding)
    ///    code without also updating this allowlist AND the ledger, the
    ///    `codes_match_the_reconciled_allowlist` assertion below fails.
    ///
    /// It is NOT a re-check of a property the type system already guarantees:
    /// the type system cannot know that `SCP-CTX-2095` means "pseudonym registry
    /// empty" or that the browser surface must not collide with a Swift/Kotlin
    /// SDK code — that is a human cross-surface-review decision, and this is where
    /// it is mechanically pinned.
    fn reconciled_code(err: &ClientError) -> &'static str {
        match err {
            ClientError::Mls(
                MlsError::ConvergentTimestampMissing | MlsError::ConvergentTimestampMalformed(_),
            ) => "SCP-CRYPTO-4040",
            ClientError::Mls(_) => "SCP-CRYPTO-4041",
            // The driver reaches no #active/#agent key, so it refuses to mint a
            // KeyPackage whose §9.7.1 attestation it cannot sign. Distinct from
            // SCP-CRYPTO-4041 so a caller can tell "this build cannot join a
            // context on its own" apart from a failed MLS operation.
            ClientError::AttestationSignerUnavailable => "SCP-CRYPTO-4042",
            ClientError::SenderKey(_) => "SCP-CRYPTO-4020",
            ClientError::EventLog(_) => "SCP-CRYPTO-4030",
            ClientError::Codec(_) => "SCP-VALID-7028",
            ClientError::UnknownContext(_) => "SCP-CTX-2082",
            ClientError::ContextAlreadyExists(_) => "SCP-CTX-2083",
            ClientError::UnsupportedMembershipChange(_) => "SCP-CTX-2084",
            ClientError::Driver(_) => "SCP-CTX-2085",
            ClientError::ChannelContentMismatch => "SCP-VALID-7029",
            ClientError::Transport(_) => "SCP-TRANS-5005",
            ClientError::PseudonymRegistryEmpty { .. } => "SCP-CTX-2095",
            ClientError::NoPendingJoinMaterial { .. } => "SCP-CTX-2086",
            ClientError::StorageBackend(_) => "SCP-STORAGE-8010",
            ClientError::StorageCorrupt(_) => "SCP-STORAGE-8011",
            ClientError::StorageIdentityMismatch(_) => "SCP-STORAGE-8012",
            ClientError::ContextPoisoned { .. } => "SCP-STORAGE-8013",
        }
    }

    /// One representative value of EVERY `ClientError` variant (plus the two
    /// `Mls` convergent-timestamp sub-cases, which take a different code from the
    /// generic `Mls(_)` catch-all). Built without a wildcard so the compiler
    /// forces this list to grow with the enum.
    fn every_variant_representative() -> Vec<ClientError> {
        // Enumerate via an exhaustive destructuring match on a placeholder so a
        // new variant breaks compilation here too, not just in `reconciled_code`.
        // (The value below is discarded; the match exists only for its
        // exhaustiveness check.)
        let probe = ClientError::ChannelContentMismatch;
        match &probe {
            ClientError::Mls(_)
            | ClientError::SenderKey(_)
            | ClientError::EventLog(_)
            | ClientError::Codec(_)
            | ClientError::UnknownContext(_)
            | ClientError::ContextAlreadyExists(_)
            | ClientError::UnsupportedMembershipChange(_)
            | ClientError::Driver(_)
            | ClientError::ChannelContentMismatch
            | ClientError::Transport(_)
            | ClientError::PseudonymRegistryEmpty { .. }
            | ClientError::NoPendingJoinMaterial { .. }
            | ClientError::StorageBackend(_)
            | ClientError::StorageCorrupt(_)
            | ClientError::StorageIdentityMismatch(_)
            | ClientError::ContextPoisoned { .. }
            | ClientError::AttestationSignerUnavailable => {}
        }
        vec![
            // Both `Mls` sub-cases (distinct 4040) plus a generic `Mls` (4041).
            ClientError::Mls(MlsError::ConvergentTimestampMissing),
            ClientError::Mls(MlsError::ConvergentTimestampMalformed("bad len".to_owned())),
            ClientError::Mls(MlsError::GroupDestroyed),
            ClientError::SenderKey(
                scp_protocol::crypto::sender_keys::SenderKeyError::EpochOverflow,
            ),
            ClientError::EventLog(scp_event_log::EventLogError::EmptyLog),
            ClientError::Codec("wire".to_owned()),
            ClientError::UnknownContext("c".to_owned()),
            ClientError::ContextAlreadyExists("c".to_owned()),
            ClientError::UnsupportedMembershipChange("c".to_owned()),
            ClientError::Driver("d".to_owned()),
            ClientError::ChannelContentMismatch,
            ClientError::Transport("t".to_owned()),
            ClientError::PseudonymRegistryEmpty {
                context_id: "c".to_owned(),
                member_count: 2,
            },
            ClientError::NoPendingJoinMaterial {
                context_id: "c".to_owned(),
            },
            ClientError::StorageBackend("s".to_owned()),
            ClientError::StorageCorrupt("s".to_owned()),
            ClientError::StorageIdentityMismatch("s".to_owned()),
            ClientError::ContextPoisoned {
                context_id: "c".to_owned(),
            },
            ClientError::AttestationSignerUnavailable,
        ]
    }

    #[test]
    fn codes_match_the_reconciled_allowlist() {
        // Positive whitelist: for every representative, the emitted code equals
        // the reconciled ledger value. Any divergence between `error_code()` and
        // the sdk-common.md ledger (a renumber, a native-code re-use regression)
        // fails here.
        for err in every_variant_representative() {
            assert_eq!(
                error_code(&err),
                reconciled_code(&err),
                "error_code() diverged from the reconciled sdk-common.md allowlist for {err:?}"
            );
        }
    }

    #[test]
    fn pseudonym_registry_empty_is_the_only_cross_surface_reuse() {
        // `SCP-CTX-2095` (pseudonym-registry-empty) is the ONE code the browser
        // surface deliberately shares with the other surfaces — same meaning on
        // native + Swift + Kotlin + ts-native. Every OTHER browser code is
        // browser-owned and cross-surface-free (verified by manual union review;
        // see the module doc). This pins the ruling.
        const INTENTIONAL_CROSS_SURFACE_REUSES: [&str; 1] = ["SCP-CTX-2095"];

        assert_eq!(
            error_code(&ClientError::PseudonymRegistryEmpty {
                context_id: "c".to_owned(),
                member_count: 2,
            }),
            INTENTIONAL_CROSS_SURFACE_REUSES[0],
        );
        // `ContextAlreadyExists` must NOT revert to native CTX-2003: that number
        // is overloaded off-native (Swift/Kotlin use it for other conditions), so
        // a fresh browser-owned code was minted.
        assert_eq!(
            error_code(&ClientError::ContextAlreadyExists("c".to_owned())),
            "SCP-CTX-2083",
        );
        assert_ne!(
            error_code(&ClientError::ContextAlreadyExists("c".to_owned())),
            "SCP-CTX-2003",
            "ContextAlreadyExists must not reuse the cross-surface-overloaded 2003"
        );
    }

    #[test]
    fn lib_rs_input_validation_code_is_pinned() {
        // The ~9 `lib.rs` wasm free-function input validators construct their
        // `JsValue` message DIRECTLY (not via `error_code`), so the allowlist test
        // above cannot see them. They all route through `WASM_INPUT_VALIDATION_CODE`
        // — pinning that one constant here pins every one of those emitters, and a
        // typo in the constant fails this test (and the allowlist test, since
        // `error_code(Codec)` returns the constant).
        assert_eq!(WASM_INPUT_VALIDATION_CODE, "SCP-VALID-7028");
        assert_eq!(
            error_code(&ClientError::Codec("wire".to_owned())),
            WASM_INPUT_VALIDATION_CODE,
            "ClientError::Codec must route through the shared lib.rs input-validation code"
        );
    }

    #[test]
    fn convergent_timestamp_family_precedes_the_generic_mls_catch_all() {
        // ADR-057 arm-ordering guard: both convergent-timestamp AAD failures
        // (wrapped in `ClientError::Mls`) must resolve to the distinct
        // SCP-CRYPTO-4040, NOT fall through to the generic SCP-CRYPTO-4041.
        for err in [
            ClientError::Mls(MlsError::ConvergentTimestampMissing),
            ClientError::Mls(MlsError::ConvergentTimestampMalformed("bad len".to_owned())),
        ] {
            assert_eq!(error_code(&err), "SCP-CRYPTO-4040");
        }
        assert_eq!(
            error_code(&ClientError::Mls(MlsError::GroupDestroyed)),
            "SCP-CRYPTO-4041"
        );
    }

    #[test]
    fn every_code_is_in_the_documented_prefix_space() {
        for err in every_variant_representative() {
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
        assert!(msg.starts_with("[SCP-CTX-2082] "), "prefix present: {msg}");
        assert!(msg.contains("ctx-x"), "message preserved: {msg}");
    }

    #[wasm_bindgen_test]
    fn map_err_threads_ok_through() {
        let ok: Result<u8, ClientError> = Ok(7);
        assert_eq!(map_err(ok).unwrap_or(0), 7);
    }
}
