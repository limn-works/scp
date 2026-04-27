//! Receiver-side [`OutletError`] envelope verification (SCP-OUT-041b).
//!
//! Spec: `.docs/specs/05-contexts.md` §5.4.4 round-6 — "Receiver lookup
//! across re-registration windows — `registration_event_id` and the
//! per-outlet LRU."
//!
//! When a receiver decodes an incoming [`OutletError`] envelope, it must:
//!
//! 1. Look up the envelope's `registration_event_id` in the per-outlet
//!    [`OutletMessageKeyLru`] (capacity
//!    [`MESSAGE_KEY_LRU_CAPACITY`] = 4 per §9.18.A).
//! 2. **Hit:** HMAC-verify the envelope's `message` field under the
//!    matched `outlet_message_key` against every key in the outlet's
//!    registered `message_catalog`. The catalog has at most 256 entries
//!    (§5.4.1), so the linear scan is O(256) per envelope and bounded.
//! 3. **Miss / no match:** reject with
//!    [`OutletErrorConstructionFailed::UnregisteredMessageKey`]. The
//!    cited registration has aged out of the LRU window (more than four
//!    re-registrations have intervened since emission), or the operator
//!    is fabricating an HMAC that does not bind to any catalog entry.
//!
//! The miss-rejection is non-negotiable: accepting the envelope on the
//! strength of its on-wire bytes alone would admit a covert-channel
//! surface where an operator could leak information by signing under a
//! never-registered key. §5.4.4 round-6 spells this out: "An error whose
//! `registration_event_id` does not hit the LRU at all — because the
//! registration has aged out — is likewise rejected with
//! `UnregisteredMessageKey`."
//!
//! [`OutletError`]: scp_protocol::context::outlets::errors::OutletError
//! [`OutletMessageKeyLru`]: super::message_key::OutletMessageKeyLru
//! [`MESSAGE_KEY_LRU_CAPACITY`]: super::message_key::MESSAGE_KEY_LRU_CAPACITY
//! [`OutletErrorConstructionFailed::UnregisteredMessageKey`]: scp_protocol::context::outlets::errors::OutletErrorConstructionFailed::UnregisteredMessageKey

use scp_protocol::context::outlets::error_codes::{
    SlugError, error_code_to_class, slug_to_class, validate_slug,
};
use scp_protocol::context::outlets::errors::{
    CatalogKey, OutletError, OutletErrorConstructionFailed,
};

use super::message_key::OutletMessageKeyLru;

/// Outcome of [`verify_outlet_error`].
///
/// On success, the envelope's HMAC was reversed against the outlet's
/// registered catalog and the matching [`CatalogKey`] is returned so
/// the receiver can resolve the catalog template and surface localized
/// prose to operator tooling. On failure the envelope is rejected per
/// §5.4.4 round-6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutletError {
    /// The catalog key whose HMAC matched the on-wire `message` field.
    pub catalog_key: CatalogKey,
}

/// Verifies an incoming [`OutletError`] envelope against an outlet's
/// per-outlet LRU and registered catalog (SCP-OUT-041b).
///
/// # Algorithm
///
/// 1. Look up `envelope.registration_event_id` in `lru`. If the lookup
///    misses, return
///    [`OutletErrorConstructionFailed::UnregisteredMessageKey`] —
///    the cited registration has aged out (or never existed).
/// 2. For each [`CatalogKey`] in `registered_keys`, compute
///    `HMAC-SHA-256(matched_outlet_message_key, key.as_str().as_bytes())[..32]`
///    via [`OutletError::compute_wire_message`] and compare against
///    `envelope.message`. The first byte-equal match resolves to that
///    catalog key.
/// 3. If no catalog key matches the HMAC, return
///    [`OutletErrorConstructionFailed::UnregisteredMessageKey`] — the
///    operator is fabricating an HMAC that does not bind to any
///    registered entry.
///
/// # Time bound
///
/// O(`registered_keys.len()`). The catalog is capped at 256 entries by
/// §5.4.1 [`CATALOG_MAX_ENTRIES`], so the worst-case scan is bounded.
/// The HMAC scan is run once per accepted envelope, not per
/// envelope-byte; receivers do not need to short-circuit further.
///
/// # Errors
///
/// Returns [`OutletErrorConstructionFailed::UnregisteredMessageKey`]
/// when:
///
/// - `envelope.registration_event_id` does not resolve in `lru` (the
///   registration has aged out of the LRU window — more than
///   [`MESSAGE_KEY_LRU_CAPACITY`] re-registrations have intervened).
/// - The HMAC of every `registered_keys` entry under the looked-up
///   key fails to byte-match `envelope.message` (no catalog binding).
///
/// The two paths share a single error variant by design: §5.4.4 round-6
/// merges the two miss conditions to deny the operator a presence
/// oracle (a distinguishable rejection would let the operator probe
/// "registration evicted vs. catalog-binding mismatch" for every
/// envelope, which is itself a side channel).
///
/// # Story
///
/// SCP-OUT-041b. Builds on SCP-OUT-024 ([`OutletError::compute_wire_message`])
/// and SCP-OUT-041a ([`OutletMessageKeyLru`]).
///
/// [`OutletMessageKeyLru`]: super::message_key::OutletMessageKeyLru
/// [`MESSAGE_KEY_LRU_CAPACITY`]: super::message_key::MESSAGE_KEY_LRU_CAPACITY
/// [`CATALOG_MAX_ENTRIES`]: scp_protocol::context::outlets::message_catalog::CATALOG_MAX_ENTRIES
pub fn verify_outlet_error(
    envelope: &OutletError,
    lru: &OutletMessageKeyLru,
    registered_keys: &[CatalogKey],
) -> Result<VerifiedOutletError, OutletErrorConstructionFailed> {
    // Step 0 (SCP-OUT-025): wire-layer slug regex check. Decoding via
    // serde permits any String value through the `slug` field; the
    // §5.4.4 regex is enforced here so a malformed slug is rejected at
    // the receiver boundary before any HMAC work runs. Symmetric with
    // `OutletError::new`'s construction-time check on the emitter side.
    if let Err(SlugError::Malformed { slug }) = validate_slug(&envelope.slug) {
        return Err(OutletErrorConstructionFailed::MalformedSlug { slug });
    }

    // Step 0b (SCP-OUT-025): defense-in-depth class/code/slug consistency
    // check via the §5.4.4 registry. A wire envelope whose `class` field
    // disagrees with `error_code_to_class(envelope.code)` or
    // `slug_to_class(envelope.slug)` is rejected as a wire-layer
    // ClassCodeMismatch — preventing an operator from emitting
    // syntactically valid but semantically inconsistent envelopes.
    if let Some(expected) = error_code_to_class(&envelope.code)
        && expected != envelope.class
    {
        return Err(OutletErrorConstructionFailed::ClassCodeMismatch {
            code_or_slug: envelope.code.clone(),
            expected,
            actual: envelope.class,
        });
    }
    if let Some(expected) = slug_to_class(&envelope.slug)
        && expected != envelope.class
    {
        return Err(OutletErrorConstructionFailed::ClassCodeMismatch {
            code_or_slug: envelope.slug.clone(),
            expected,
            actual: envelope.class,
        });
    }

    // Step 1: registration_event_id must hit the LRU. The §5.4.4 round-6
    // miss-path is non-negotiable: a miss is rejected so the operator
    // cannot fabricate envelopes under never-registered keys.
    let outlet_message_key = lru.get(&envelope.registration_event_id).ok_or_else(|| {
        OutletErrorConstructionFailed::UnregisteredMessageKey {
            // Surface the slug as a tracing aid; the catalog_key plaintext
            // is not on the wire (the HMAC opacity is the whole point).
            // The slug field is class-prefixed and matches the catalog-key
            // grammar, so it is a reasonable diagnostic.
            catalog_key: envelope.slug.clone(),
        }
    })?;

    // Step 2: HMAC-reverse against every registered catalog key. The
    // catalog is capped at §5.4.1 CATALOG_MAX_ENTRIES = 256, so this
    // loop is bounded.
    for key in registered_keys {
        let candidate = OutletError::compute_wire_message(outlet_message_key, key);
        if candidate == envelope.message {
            return Ok(VerifiedOutletError {
                catalog_key: key.clone(),
            });
        }
    }

    // Step 3: no catalog binding. The operator emitted an HMAC that does
    // not match any registered key under the LRU-looked-up
    // outlet_message_key — a wire-layer rejection per §5.4.4 round-6.
    Err(OutletErrorConstructionFailed::UnregisteredMessageKey {
        catalog_key: envelope.slug.clone(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use scp_protocol::context::outlets::OutletId;
    use scp_protocol::context::outlets::errors::{
        OUTLET_MESSAGE_KEY_LEN, OutletErrorClass, OutletErrorNewOpts, PAD_NONCE_LEN,
        REGISTRATION_EVENT_ID_LEN, RetryPolicy,
    };

    use super::super::message_key::{MESSAGE_KEY_LRU_CAPACITY, OutletMessageKeyLru};

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    fn registered_keys() -> Vec<CatalogKey> {
        vec![
            CatalogKey::try_new("authorization.denied").unwrap(),
            CatalogKey::try_new("authorization.amplification-violation").unwrap(),
            CatalogKey::try_new("protocol.outlet-not-found").unwrap(),
            CatalogKey::try_new("execution.handler-panic").unwrap(),
        ]
    }

    fn build_envelope(
        outlet_id_str: &str,
        outlet_message_key: &[u8; OUTLET_MESSAGE_KEY_LEN],
        registration_event_id: [u8; REGISTRATION_EVENT_ID_LEN],
        catalog_key_str: &str,
    ) -> OutletError {
        let outlet_id: OutletId = outlet_id_str.to_owned();
        let key = CatalogKey::try_new(catalog_key_str).unwrap();
        let registered = registered_keys();
        OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key,
            registration_event_id,
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: "SCP-TOOL-6110",
            slug: "authorization.denied",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: [0x55; PAD_NONCE_LEN],
        })
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // Hit path — LRU resolves and HMAC reverses to a catalog entry.
    // -----------------------------------------------------------------------

    #[test]
    fn verify_returns_catalog_key_on_lru_hit_and_hmac_match() {
        let outlet_message_key = [0x42; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];
        let envelope = build_envelope(
            "outlet-test",
            &outlet_message_key,
            registration_event_id,
            "authorization.denied",
        );

        let mut lru = OutletMessageKeyLru::new();
        lru.insert(registration_event_id, outlet_message_key);

        let registered = registered_keys();
        let verified =
            verify_outlet_error(&envelope, &lru, &registered).expect("verify must succeed");
        assert_eq!(
            verified.catalog_key,
            CatalogKey::try_new("authorization.denied").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Miss path — registration_event_id not in LRU.
    // -----------------------------------------------------------------------

    #[test]
    fn verify_rejects_when_registration_event_id_missing_from_lru() {
        let outlet_message_key = [0x42; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];
        let envelope = build_envelope(
            "outlet-test",
            &outlet_message_key,
            registration_event_id,
            "authorization.denied",
        );

        // Empty LRU — guaranteed miss.
        let lru = OutletMessageKeyLru::new();
        let registered = registered_keys();
        let result = verify_outlet_error(&envelope, &lru, &registered);
        assert!(matches!(
            result,
            Err(OutletErrorConstructionFailed::UnregisteredMessageKey { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Miss path — LRU hit, but HMAC does not match any registered catalog key.
    // -----------------------------------------------------------------------

    #[test]
    fn verify_rejects_when_hmac_does_not_match_any_catalog_entry() {
        // Construct an envelope under a key that IS registered; then verify
        // it against a *different* registered_keys list that does NOT
        // include the original catalog key. The LRU lookup hits (correct
        // outlet_message_key) but the HMAC reverse fails for every key in
        // the verifier's catalog — UnregisteredMessageKey.
        let outlet_message_key = [0x42; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];
        let envelope = build_envelope(
            "outlet-test",
            &outlet_message_key,
            registration_event_id,
            "authorization.denied",
        );

        let mut lru = OutletMessageKeyLru::new();
        lru.insert(registration_event_id, outlet_message_key);

        // Disjoint catalog — does not contain "authorization.denied".
        let disjoint_catalog = vec![
            CatalogKey::try_new("input.schema-violation").unwrap(),
            CatalogKey::try_new("output.too-large").unwrap(),
        ];

        let result = verify_outlet_error(&envelope, &lru, &disjoint_catalog);
        assert!(matches!(
            result,
            Err(OutletErrorConstructionFailed::UnregisteredMessageKey { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Cross-registration LRU regression — §5.4.4 round-6 acceptance criterion.
    // -----------------------------------------------------------------------

    /// AC-10: Construct an OutletError signed under registration R1 (event-log
    /// id E1). Re-register four times, producing R2..R5 with event-log ids
    /// E2..E5. The LRU now holds {R2, R3, R4, R5} (R1 evicted at capacity).
    /// The R1-signed envelope is rejected; a fresh envelope signed under R3
    /// resolves successfully.
    #[test]
    fn cross_registration_lru_regression_evicts_oldest_and_resolves_resident() {
        // Five distinct registrations with distinct keys.
        let e1 = [0x01; REGISTRATION_EVENT_ID_LEN];
        let e2 = [0x02; REGISTRATION_EVENT_ID_LEN];
        let e3 = [0x03; REGISTRATION_EVENT_ID_LEN];
        let e4 = [0x04; REGISTRATION_EVENT_ID_LEN];
        let e5 = [0x05; REGISTRATION_EVENT_ID_LEN];
        let k1 = [0x11; OUTLET_MESSAGE_KEY_LEN];
        let k2 = [0x22; OUTLET_MESSAGE_KEY_LEN];
        let k3 = [0x33; OUTLET_MESSAGE_KEY_LEN];
        let k4 = [0x44; OUTLET_MESSAGE_KEY_LEN];
        let k5 = [0x55; OUTLET_MESSAGE_KEY_LEN];

        // R1 emits an envelope; it is in flight when R2..R5 land.
        let envelope_r1 = build_envelope("outlet-x", &k1, e1, "authorization.denied");
        // A fresh envelope under R3 is emitted while R3 is the current
        // registration; receiver sees it after R5 has landed.
        let envelope_r3 = build_envelope("outlet-x", &k3, e3, "authorization.denied");

        // Receiver state — accept R1..R5 in order.
        let mut lru = OutletMessageKeyLru::new();
        assert!(lru.insert(e1, k1).is_none(), "R1 inserts cleanly");
        assert!(lru.insert(e2, k2).is_none(), "R2 inserts cleanly");
        assert!(lru.insert(e3, k3).is_none(), "R3 inserts cleanly");
        assert!(lru.insert(e4, k4).is_none(), "R4 inserts cleanly");
        // At MESSAGE_KEY_LRU_CAPACITY = 4. R5 must evict R1.
        assert_eq!(lru.insert(e5, k5), Some(e1), "R5 evicts oldest (R1)");
        assert_eq!(lru.len(), MESSAGE_KEY_LRU_CAPACITY);

        let registered = registered_keys();

        // R1-signed envelope rejected (registration aged out).
        let r1_result = verify_outlet_error(&envelope_r1, &lru, &registered);
        assert!(matches!(
            r1_result,
            Err(OutletErrorConstructionFailed::UnregisteredMessageKey { .. })
        ));

        // R3-signed envelope resolves successfully.
        let r3_verified = verify_outlet_error(&envelope_r3, &lru, &registered)
            .expect("R3 envelope must verify under resident registration");
        assert_eq!(
            r3_verified.catalog_key,
            CatalogKey::try_new("authorization.denied").unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Per-context distinctness — same catalog_key in two contexts produces
    // distinct wire bytes (defense-in-depth that the receiver path agrees).
    // -----------------------------------------------------------------------

    #[test]
    fn same_catalog_key_in_two_contexts_yields_distinct_wire_messages() {
        // Two contexts are simulated by two distinct outlet_message_keys
        // (each context's MLS exporter produces an independent key per
        // §5.4.4 round-5). A receiver that holds only ctx_a's key can
        // never reverse ctx_b's wire bytes against the catalog — even
        // though both envelopes select the same catalog entry.
        let outlet_message_key_a = [0xAA; OUTLET_MESSAGE_KEY_LEN];
        let outlet_message_key_b = [0xBB; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];
        let env_a = build_envelope(
            "outlet-test",
            &outlet_message_key_a,
            registration_event_id,
            "authorization.denied",
        );
        let env_b = build_envelope(
            "outlet-test",
            &outlet_message_key_b,
            registration_event_id,
            "authorization.denied",
        );

        // The wire bytes differ (per-context keying).
        assert_ne!(
            env_a.message, env_b.message,
            "per-context keying must produce distinct wire bytes for the same catalog key"
        );

        // ctx_a's LRU verifies env_a but NOT env_b.
        let mut lru_a = OutletMessageKeyLru::new();
        lru_a.insert(registration_event_id, outlet_message_key_a);
        let registered = registered_keys();
        assert!(verify_outlet_error(&env_a, &lru_a, &registered).is_ok());
        // env_b's HMAC was computed under ctx_b's key — the LRU lookup
        // hits (same registration_event_id) but the HMAC reverse fails.
        let res_b = verify_outlet_error(&env_b, &lru_a, &registered);
        assert!(matches!(
            res_b,
            Err(OutletErrorConstructionFailed::UnregisteredMessageKey { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // BH5-B2 grace-window regression — same catalog_key on same outlet at
    // epoch E+1 produces the SAME wire bytes as at epoch E (the pinned key
    // never re-derives across grace-window epoch transitions).
    // -----------------------------------------------------------------------

    #[test]
    fn pinned_key_yields_identical_wire_message_across_epoch_grace_window() {
        // Simulate: at epoch E the outlet pins outlet_message_key K. The
        // receiver caches K against E1 in the LRU. At epoch E+1 (a grace-
        // window MLS epoch transition) the outlet emits another error
        // selecting the same catalog key. The pinned K does NOT re-derive,
        // so the wire bytes are byte-identical to the epoch-E emission —
        // closing the BH5-B2 covert channel.
        let outlet_message_key = [0x42; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];

        let env_at_e = build_envelope(
            "outlet-test",
            &outlet_message_key,
            registration_event_id,
            "authorization.denied",
        );
        let env_at_e_plus_1 = build_envelope(
            "outlet-test",
            &outlet_message_key, // SAME key (pinned at acceptance, not re-derived)
            registration_event_id,
            "authorization.denied",
        );

        assert_eq!(
            env_at_e.message, env_at_e_plus_1.message,
            "BH5-B2 closure: pinned outlet_message_key produces identical wire bytes \
             for the same catalog key across grace-window epoch transitions",
        );

        // Both envelopes verify under the same LRU entry.
        let mut lru = OutletMessageKeyLru::new();
        lru.insert(registration_event_id, outlet_message_key);
        let registered = registered_keys();
        verify_outlet_error(&env_at_e, &lru, &registered).expect("E verifies");
        verify_outlet_error(&env_at_e_plus_1, &lru, &registered).expect("E+1 verifies");
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-025 — registry-driven wire-deserialization checks.
    //
    // The receiver MUST run the §5.4.4 registry through every wire envelope:
    //
    // - `validate_slug` rejects malformed slugs at the boundary (Step 0).
    // - `error_code_to_class` and `slug_to_class` reject envelopes whose
    //   `class` field disagrees with the registry mapping (Step 0b).
    //
    // Both checks run before any HMAC work so a malformed envelope cannot
    // even probe the LRU side channel.
    // -----------------------------------------------------------------------

    #[test]
    fn verify_rejects_envelope_with_uppercase_slug() {
        // SCP-OUT-025: a wire envelope whose `slug` field is uppercase
        // fails the §5.4.4 regex. Construction-time it could not have been
        // emitted by `OutletError::new` — but the wire path is exposed to
        // operator-fabricated envelopes whose serde decode bypasses
        // construction. `verify_outlet_error` MUST reject malformed slugs
        // via `validate_slug` before any HMAC reverse runs.
        let outlet_message_key = [0x42; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];
        let mut envelope = build_envelope(
            "outlet-test",
            &outlet_message_key,
            registration_event_id,
            "authorization.denied",
        );
        // Tamper with the slug field after construction — mimics a
        // wire-deserialized envelope whose serde decode permitted any
        // String through the slug slot.
        envelope.slug = "AUTHORIZATION.DENIED".to_owned();

        let mut lru = OutletMessageKeyLru::new();
        lru.insert(registration_event_id, outlet_message_key);
        let registered = registered_keys();
        let result = verify_outlet_error(&envelope, &lru, &registered);
        match result {
            Err(OutletErrorConstructionFailed::MalformedSlug { slug }) => {
                assert_eq!(slug, "AUTHORIZATION.DENIED");
            }
            other => panic!("expected MalformedSlug, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_wire_envelope_with_class_code_mismatch() {
        // SCP-OUT-025: a wire envelope whose `class` field disagrees
        // with `error_code_to_class(envelope.code)` is rejected as
        // ClassCodeMismatch. Models an operator-fabricated envelope
        // that sets the class field to mislead receivers about which
        // sealed-class branch to dispatch on.
        let outlet_message_key = [0x42; OUTLET_MESSAGE_KEY_LEN];
        let registration_event_id = [0xE1; REGISTRATION_EVENT_ID_LEN];
        let mut envelope = build_envelope(
            "outlet-test",
            &outlet_message_key,
            registration_event_id,
            "authorization.denied",
        );
        // Tamper: code stays 6110 (Authorization per registry) but
        // overwrite the class to Input — the wire-layer mismatch must
        // be rejected.
        envelope.class = scp_protocol::context::outlets::errors::OutletErrorClass::Input;

        let mut lru = OutletMessageKeyLru::new();
        lru.insert(registration_event_id, outlet_message_key);
        let registered = registered_keys();
        let result = verify_outlet_error(&envelope, &lru, &registered);
        match result {
            Err(OutletErrorConstructionFailed::ClassCodeMismatch {
                code_or_slug,
                expected,
                actual,
            }) => {
                use scp_protocol::context::outlets::errors::OutletErrorClass;
                // The code check fires first (envelope.code = 6110).
                assert_eq!(code_or_slug, "SCP-TOOL-6110");
                assert_eq!(expected, OutletErrorClass::Authorization);
                assert_eq!(actual, OutletErrorClass::Input);
            }
            other => panic!("expected ClassCodeMismatch, got {other:?}"),
        }
    }
}
